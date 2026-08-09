package io.mailmite.core;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;

/**
 * Iterates over all decompiled functions in a SqliteStore, calls an LLM provider
 * for each one (respecting a cache), and writes findings to the LlmFindings table.
 *
 * <p>In FIND_VULNS mode the LLM is asked to return structured JSON. Any vulnerabilities
 * it returns are <em>also</em>:
 * <ul>
 *   <li>Inserted into the {@code Vulnerabilities} table with rule IDs like
 *       {@code LLM-XSS-001}, so they appear in the same UI tab as MSTG findings;</li>
 *   <li>Persisted to a {@link LearnedRulesStore} so future scans without LLM
 *       enrichment will detect the same pattern statically.</li>
 * </ul>
 */
public class LlmEnricher {

    private static final Logger log = LoggerFactory.getLogger(LlmEnricher.class);

    private static final String SYSTEM_AUTO_FIX =
            "You are an expert iOS reverse engineer. Translate the supplied decompiled C++ " +
            "pseudocode back to idiomatic %s. Preserve method names and global variables. " +
            "You may rename local variables for readability. Return only the translated code, " +
            "no commentary.";

    private static final String SYSTEM_SUMMARIZE =
            "You are an expert iOS security researcher. Summarise what the supplied decompiled " +
            "function does in 2-4 sentences of plain English. Focus on its purpose, key " +
            "operations, and any notable patterns. If it appears to belong to a known framework, " +
            "say so. Format as plain text, no markdown headers.";

    private static final String SYSTEM_FIND_VULNS =
            "You are an expert iOS mobile security auditor analysing ONE Ghidra-decompiled function (not source code).\n\n" +
            "Detect real security vulnerabilities only: memory safety, missing input validation, " +
            "auth bypass, hardcoded secrets, insecure API usage, injection (SQL/command/format string), " +
            "XSS via evaluateJavaScript/postMessage, path traversal, weak crypto, insecure keychain " +
            "(missing kSecAttrAccessible), sensitive logging. Skip style or readability issues.\n\n" +
            "RESPONSE FORMAT (mandatory):\n" +
            "- Your ENTIRE response MUST be a single JSON object. The first character MUST be '{'.\n" +
            "- Do NOT write chain-of-thought, analysis, preamble, markdown fences, or trailing commentary.\n" +
            "- Reason silently; emit JSON only. If unsure, return {\"vulnerabilities\": []}.\n\n" +
            "Schema:\n" +
            "{\n" +
            "  \"vulnerabilities\": [\n" +
            "    {\n" +
            "      \"scope\": \"XSS|INJECTION|PATH-TRAVERSAL|KEYCHAIN|INSECURE-STORAGE|CRYPTO|AUTH|INSECURE-LOG|NETWORK|WEBVIEW|URLSCHEME|DEBUG|IPC|INPUT-VALIDATION|MEMORY-SAFETY|OTHER\",\n" +
            "      \"title\": \"Short title under 80 chars\",\n" +
            "      \"severity\": \"CRITICAL|HIGH|MEDIUM|LOW\",\n" +
            "      \"cvss\": 7.5,\n" +
            "      \"cwe\": \"CWE-79\",\n" +
            "      \"description\": \"1-2 sentences explaining the vulnerability\",\n" +
            "      \"evidence\": \"exact short code snippet from the function (under 200 chars)\",\n" +
            "      \"poc_steps\": \"1. step\\n2. step\\n3. step\",\n" +
            "      \"remediation\": \"1-2 sentence fix\",\n" +
            "      \"detection_regex\": \"Java Pattern regex matching this anti-pattern in similar decompiled code\"\n" +
            "    }\n" +
            "  ]\n" +
            "}\n\n" +
            "CRITICAL detection_regex rules — your regex runs against Ghidra's C-like pseudocode, NOT source code:\n" +
            "1. Must compile with java.util.regex.Pattern.compile()\n" +
            "2. In decompiled C, statement order is REVERSED from source. Source `func(arg)` becomes:\n" +
            "       pcVar3 = \"...arg literal...\";\n" +
            "       _objc_msgSend(obj, PTR_s_func_xxx, pcVar3, 0);\n" +
            "   So write order-agnostic patterns: `(?:A[\\s\\S]{0,2000}B|B[\\s\\S]{0,2000}A)`\n" +
            "3. Objective-C selectors appear via pointer constants like `PTR_s_evaluateJavaScript_completionHan_*` —\n" +
            "   match the bare selector name (e.g. `evaluateJavaScript`), NOT `[obj evaluateJavaScript:...]` syntax.\n" +
            "4. String literals in decompiled output keep their `\\\"` escapes but inner single quotes become `\\\\'` —\n" +
            "   avoid anchoring on inner punctuation, prefer keyword tokens.\n" +
            "5. Use generous distance windows: `[\\s\\S]{0,2000}` between tokens (decompiled C has many register spills).\n" +
            "6. Your regex MUST match the supplied function's decompiled code (it will be auto-validated;\n" +
            "   regexes that don't match are dropped). Test mentally against the input before responding.\n" +
            "7. Escape regex metacharacters in literal strings: . ( ) [ ] * + ? { } | ^ $ \\\\\n" +
            "8. Aim 40-300 chars; specific enough to avoid false positives, generic enough to fire on similar code.\n\n" +
            "If no real vulnerabilities, output exactly: {\"vulnerabilities\": []}";

    private final LlmProvider provider;
    private final LlmMode     mode;
    private final LlmCache    cache;
    private final boolean     isSwift;
    private final LearnedRulesStore rulesStore;

    public LlmEnricher(LlmProvider provider, LlmMode mode, LlmCache cache, boolean isSwift) {
        this(provider, mode, cache, isSwift, new LearnedRulesStore());
    }

    public LlmEnricher(LlmProvider provider, LlmMode mode, LlmCache cache, boolean isSwift,
                       LearnedRulesStore rulesStore) {
        this.provider   = provider;
        this.mode       = mode;
        this.cache      = cache;
        this.isSwift    = isSwift;
        this.rulesStore = rulesStore;
    }

    public void enrich(SqliteStore store, String executableName) {
        String systemPrompt = buildSystemPrompt();
        List<SqliteStore.DecompilationResult> fns = store.getAllDecompiledFunctions(executableName);
        log.info("LLM enrichment: mode={} provider={} functions={}",
                mode, provider.getClass().getSimpleName(), fns.size());

        int cached = 0, called = 0, errors = 0, totalVulns = 0, newRules = 0;

        for (SqliteStore.DecompilationResult fn : fns) {
            if (fn.decompiledCode() == null || fn.decompiledCode().isBlank()) continue;

            // PROMPT_VERSION bumped whenever the system prompt changes — invalidates the cache.
            String hash = sha256(fn.decompiledCode() + "|" + mode.name() + "|v4");

            String finding = cache.get(hash).orElse(null);
            if (finding != null) {
                cached++;
            } else {
                try {
                    finding = provider.complete(systemPrompt, fn.decompiledCode());
                    cache.put(hash, finding);
                    called++;
                } catch (LlmProvider.LlmException e) {
                    log.warn("LLM call failed for {}.{}: {}", fn.className(), fn.functionName(), e.getMessage());
                    errors++;
                    continue;
                }
            }

            // Always store the raw output in LlmFindings (preserves backward compat / LLM tab)
            store.insertLlmFinding(fn.functionName(), fn.className(), executableName,
                    mode.name(), finding, hash);

            // In FIND_VULNS mode, try to parse JSON and promote to Vulnerabilities table
            if (mode == LlmMode.FIND_VULNS) {
                int[] counts = processVulnsJson(finding, fn, store, executableName);
                totalVulns += counts[0];
                newRules   += counts[1];
            }
        }
        log.info("LLM enrichment done: cached={} api_calls={} errors={} vulnerabilities={} new_learned_rules={}",
                cached, called, errors, totalVulns, newRules);
    }

    // ── JSON parsing → Vulnerabilities + learned rules ───────────────────────

    /**
     * Parses the LLM JSON output, inserts each vulnerability into the
     * {@code Vulnerabilities} table, and persists a corresponding detection
     * rule in {@link LearnedRulesStore}.
     *
     * @return [vulnerabilitiesInserted, newRulesPersisted]
     */
    private int[] processVulnsJson(String raw, SqliteStore.DecompilationResult fn,
                                    SqliteStore store, String executableName) {
        JsonObject root = extractVulnsJson(raw);
        if (root == null) {
            log.debug("LLM did not return recoverable vulnerabilities JSON for {}.{}",
                    fn.className(), fn.functionName());
            return new int[]{0, 0};
        }

        JsonArray arr;
        try { arr = root.getAsJsonArray("vulnerabilities"); }
        catch (Exception e) { return new int[]{0, 0}; }

        int vulnsInserted = 0;
        int rulesAdded = 0;
        int rulesBefore = rulesStore.size();

        for (JsonElement el : arr) {
            JsonObject v;
            try { v = el.getAsJsonObject(); } catch (Exception ex) { continue; }

            String scope        = optString(v, "scope", "OTHER").toUpperCase();
            String title        = optString(v, "title", "Unspecified LLM finding");
            String severity     = optString(v, "severity", "MEDIUM").toUpperCase();
            double cvss         = optDouble(v, "cvss", defaultCvss(severity));
            String cwe          = optString(v, "cwe", "");
            String description  = optString(v, "description", "");
            String evidence     = optString(v, "evidence", "");
            String pocSteps     = optString(v, "poc_steps", "");
            String remediation  = optString(v, "remediation", "");
            String detectionRe  = optString(v, "detection_regex", "");

            String category = scopeToCategory(scope);
            String functionLocation = (fn.className() == null ? "" : fn.className() + ".") + fn.functionName();
            String referenceUrl = "LLM-discovered " + java.time.LocalDate.now() +
                                  " from function " + functionLocation;

            String ruleId = null;
            String validationStatus = "MISSING_REGEX";
            if (!detectionRe.isBlank()) {
                // Self-validate: the regex MUST match the source function it was extracted from,
                // otherwise it would never fire on a future scan and shouldn't be persisted.
                if (regexMatchesSource(detectionRe, fn.decompiledCode())) {
                    ruleId = rulesStore.addRule(
                            scope, title, category, severity, cvss, cwe,
                            description, remediation,
                            "DECOMPILED", detectionRe,
                            pocSteps, referenceUrl);
                    validationStatus = ruleId != null ? "OK" : "INVALID_REGEX";
                } else {
                    validationStatus = "REGEX_FAILED_SELF_TEST";
                    log.info("Dropping non-matching regex for {}.{} (scope={}): {}",
                            fn.className(), fn.functionName(), scope,
                            detectionRe.length() > 100 ? detectionRe.substring(0, 100) + "…" : detectionRe);
                }
            }
            // If regex was missing/invalid/failed self-test, still record the finding with a synthetic id
            if (ruleId == null) {
                ruleId = "LLM-" + scope + "-ADHOC";
            }
            log.debug("Vulnerability {} ({}): {}", ruleId, validationStatus, title);

            Vulnerability finding = new Vulnerability(
                    ruleId, title, category, severity, cvss, cwe,
                    description, "FUNCTION", fn.functionName(),
                    truncate(evidence, 240), functionLocation,
                    pocSteps, remediation, referenceUrl);
            store.insertVulnerability(finding, executableName);
            vulnsInserted++;
        }
        rulesAdded = rulesStore.size() - rulesBefore;
        return new int[]{vulnsInserted, rulesAdded};
    }

    private static String optString(JsonObject o, String key, String def) {
        if (!o.has(key) || o.get(key).isJsonNull()) return def;
        try { return o.get(key).getAsString(); } catch (Exception e) { return def; }
    }
    private static double optDouble(JsonObject o, String key, double def) {
        if (!o.has(key) || o.get(key).isJsonNull()) return def;
        try { return o.get(key).getAsDouble(); } catch (Exception e) { return def; }
    }

    private static double defaultCvss(String severity) {
        return switch (severity) {
            case "CRITICAL" -> 9.1;
            case "HIGH"     -> 7.5;
            case "MEDIUM"   -> 5.3;
            case "LOW"      -> 3.7;
            default          -> 4.0;
        };
    }

    /** Map free-form scope to the seven first-class categories used by the UI. */
    private static String scopeToCategory(String scope) {
        return switch (scope) {
            case "XSS", "INJECTION", "PATH-TRAVERSAL", "INPUT-VALIDATION", "MEMORY-SAFETY"
                    -> "CODE";
            case "KEYCHAIN", "INSECURE-STORAGE", "INSECURE-LOG", "IPC"
                    -> "STORAGE";
            case "CRYPTO"   -> "CRYPTO";
            case "AUTH"     -> "AUTH";
            case "NETWORK"  -> "NETWORK";
            case "WEBVIEW", "URLSCHEME" -> "PLATFORM";
            case "DEBUG"    -> "RESILIENCE";
            default         -> "CODE";
        };
    }

    /**
     * Returns true if the LLM-supplied regex actually fires against the function it
     * was extracted from. Persisting a regex that fails this self-test guarantees
     * it would never fire on future scans either — better to drop it.
     */
    private static boolean regexMatchesSource(String regex, String sourceCode) {
        if (regex == null || sourceCode == null) return false;
        try {
            return java.util.regex.Pattern.compile(regex).matcher(sourceCode).find();
        } catch (java.util.regex.PatternSyntaxException ex) {
            return false;
        }
    }

    /**
     * Recover a {@code {"vulnerabilities":[...]}} object from messy LLM output:
     * clean JSON, markdown fences, prose preamble + trailing JSON, or truncated JSON.
     * Returns {@code null} when no recoverable object is found.
     */
    static JsonObject extractVulnsJson(String raw) {
        if (raw == null || raw.isBlank()) return null;

        String text = raw.trim();

        // 1) Whole response (optionally fence-wrapped)
        JsonObject direct = tryParseVulnsObject(stripCodeFences(text));
        if (direct != null) return direct;

        // 2) Any fenced ```json ... ``` block in the response
        int searchFrom = 0;
        while (true) {
            int fence = indexOfIgnoreCase(text, "```", searchFrom);
            if (fence < 0) break;
            int afterOpen = fence + 3;
            // skip optional language tag
            int nl = text.indexOf('\n', afterOpen);
            if (nl < 0) break;
            String lang = text.substring(afterOpen, nl).trim();
            if (!lang.isEmpty() && !lang.equalsIgnoreCase("json")) {
                // still allow non-json fences that contain our schema
            }
            int close = text.indexOf("```", nl + 1);
            if (close < 0) break;
            JsonObject fromFence = tryParseVulnsObject(text.substring(nl + 1, close).trim());
            if (fromFence != null) return fromFence;
            searchFrom = close + 3;
        }

        // 3) Last embedded {"vulnerabilities": ...} (prose + JSON), with truncation repair
        int idx = lastIndexOfVulnsObject(text);
        if (idx >= 0) {
            String candidate = extractBalancedOrRepair(text, idx);
            JsonObject embedded = tryParseVulnsObject(candidate);
            if (embedded != null) return embedded;
        }

        return null;
    }

    /** Package-visible for unit tests — same recovery pipeline as promotion. */
    static String extractVulnsJsonString(String raw) {
        JsonObject o = extractVulnsJson(raw);
        return o == null ? null : o.toString();
    }

    private static JsonObject tryParseVulnsObject(String json) {
        if (json == null || json.isBlank()) return null;
        String t = json.trim();
        if (!t.startsWith("{")) return null;
        try {
            JsonObject root = JsonParser.parseString(t).getAsJsonObject();
            if (!root.has("vulnerabilities") || !root.get("vulnerabilities").isJsonArray()) return null;
            return root;
        } catch (Exception e) {
            return null;
        }
    }

    /** Index of the last `{` that begins a `"vulnerabilities"` object. */
    private static int lastIndexOfVulnsObject(String text) {
        int best = -1;
        int from = 0;
        while (from < text.length()) {
            int key = text.indexOf("\"vulnerabilities\"", from);
            if (key < 0) break;
            // walk back over whitespace to an opening brace
            int i = key - 1;
            while (i >= 0 && Character.isWhitespace(text.charAt(i))) i--;
            if (i >= 0 && text.charAt(i) == '{') best = i;
            from = key + 1;
        }
        return best;
    }

    /**
     * Return the balanced JSON substring starting at {@code start}, or a repaired
     * truncation that keeps only complete vulnerability objects.
     */
    private static String extractBalancedOrRepair(String text, int start) {
        if (start < 0 || start >= text.length() || text.charAt(start) != '{') return null;

        String balanced = extractBalanced(text, start);
        if (balanced != null) return balanced;

        // Truncated — salvage complete objects inside the vulnerabilities array
        return repairTruncatedJson(text.substring(start));
    }

    /** Balanced `{...}` starting at {@code start}, or {@code null} if unclosed. */
    private static String extractBalanced(String text, int start) {
        int depth = 0;
        boolean inStr = false;
        boolean esc = false;
        for (int i = start; i < text.length(); i++) {
            char c = text.charAt(i);
            if (inStr) {
                if (esc) esc = false;
                else if (c == '\\') esc = true;
                else if (c == '"') inStr = false;
            } else {
                if (c == '"') inStr = true;
                else if (c == '{') depth++;
                else if (c == '}') {
                    depth--;
                    if (depth == 0) return text.substring(start, i + 1);
                }
            }
        }
        return null;
    }

    /**
     * Rebuild {@code {"vulnerabilities":[...complete objects...]}} from a truncated
     * fragment. Incomplete trailing objects are dropped.
     */
    static String repairTruncatedJson(String fragment) {
        if (fragment == null || fragment.isBlank()) return null;
        int key = fragment.indexOf("\"vulnerabilities\"");
        if (key < 0) return null;
        int arrStart = fragment.indexOf('[', key);
        if (arrStart < 0) return "{\"vulnerabilities\":[]}";

        StringBuilder entries = new StringBuilder();
        int i = arrStart + 1;
        while (i < fragment.length()) {
            while (i < fragment.length() && Character.isWhitespace(fragment.charAt(i))) i++;
            if (i >= fragment.length()) break;
            char c = fragment.charAt(i);
            if (c == ']') break;
            if (c == ',') { i++; continue; }
            if (c != '{') break;
            String obj = extractBalanced(fragment, i);
            if (obj == null) break; // truncated mid-object — stop
            if (!entries.isEmpty()) entries.append(',');
            entries.append(obj);
            i += obj.length();
        }
        return "{\"vulnerabilities\":[" + entries + "]}";
    }

    /** Strip a leading/trailing markdown fence wrapping the whole string. */
    private static String stripCodeFences(String s) {
        if (s == null) return "";
        String t = s.trim();
        if (t.startsWith("```")) {
            int firstNl = t.indexOf('\n');
            if (firstNl > 0) t = t.substring(firstNl + 1);
            int closing = t.lastIndexOf("```");
            if (closing > 0) t = t.substring(0, closing);
        }
        return t.trim();
    }

    private static int indexOfIgnoreCase(String haystack, String needle, int from) {
        return haystack.toLowerCase().indexOf(needle.toLowerCase(), from);
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private String buildSystemPrompt() {
        return switch (mode) {
            case AUTO_FIX   -> String.format(SYSTEM_AUTO_FIX,
                                    isSwift ? "Swift" : "Objective-C",
                                    isSwift ? "Swift" : "Objective-C");
            case SUMMARIZE  -> SYSTEM_SUMMARIZE;
            case FIND_VULNS -> SYSTEM_FIND_VULNS;
        };
    }

    private static String sha256(String input) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                    .digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
