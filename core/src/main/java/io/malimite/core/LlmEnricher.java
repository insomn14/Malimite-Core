package io.malimite.core;

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
 *
 * <p>System prompts and user envelopes are selected by {@link PackagePlatform} and
 * decompiler origin ({@code JADX} vs {@code GHIDRA}) so Android APK analysis is not
 * treated as iOS/ObjC.
 */
public class LlmEnricher {

    private static final Logger log = LoggerFactory.getLogger(LlmEnricher.class);

    /** Bump when system prompts or envelope format change — invalidates LLM cache. */
    static final String PROMPT_VERSION = "v6";

    private static final String JSON_RESPONSE_FORMAT =
            "RESPONSE FORMAT (mandatory):\n" +
            "- Your ENTIRE response MUST be a single JSON object. The first character MUST be '{'.\n" +
            "- Do NOT write chain-of-thought, analysis, preamble, markdown fences, or trailing commentary.\n" +
            "- Reason silently; emit JSON only. If unsure, return {\"vulnerabilities\": []}.\n\n" +
            "Schema:\n" +
            "{\n" +
            "  \"vulnerabilities\": [\n" +
            "    {\n" +
            "      \"scope\": \"XSS|INJECTION|PATH-TRAVERSAL|KEYCHAIN|INSECURE-STORAGE|CRYPTO|AUTH|INSECURE-LOG|NETWORK|WEBVIEW|URLSCHEME|DEBUG|IPC|EXPORTED-COMPONENT|SQL-INJECTION|KEYSTORE|CLEARTEXT|INPUT-VALIDATION|MEMORY-SAFETY|JNI|OTHER\",\n" +
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
            "Never use ellipsis placeholders (\"...\", \"…\") for description, evidence, poc_steps, " +
            "remediation, or detection_regex. If you cannot fill a field, omit the vulnerability.\n\n";

    // ── iOS prompts (Ghidra Mach-O / ObjC) ────────────────────────────────────

    private static final String IOS_AUTO_FIX =
            "You are an expert iOS reverse engineer. Translate the supplied decompiled C++ " +
            "pseudocode back to idiomatic %s. Preserve method names and global variables. " +
            "You may rename local variables for readability. Return only the translated code, " +
            "no commentary.";

    private static final String IOS_SUMMARIZE =
            "You are an expert iOS security researcher. Summarise what the supplied decompiled " +
            "function does in 2-4 sentences of plain English. Focus on its purpose, key " +
            "operations, and any notable patterns. If it appears to belong to a known framework, " +
            "say so. Format as plain text, no markdown headers.";

    private static final String IOS_FIND_VULNS =
            "You are an expert iOS mobile security auditor analysing ONE Ghidra-decompiled function (not source code).\n\n" +
            "Detect real security vulnerabilities only: memory safety, missing input validation, " +
            "auth bypass, hardcoded secrets, insecure API usage, injection (SQL/command/format string), " +
            "XSS via evaluateJavaScript/postMessage, path traversal, weak crypto, insecure keychain " +
            "(missing kSecAttrAccessible), sensitive logging. Skip style or readability issues.\n\n" +
            JSON_RESPONSE_FORMAT +
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

    // ── Android JADX (Java) prompts ──────────────────────────────────────────

    private static final String ANDROID_JAVA_AUTO_FIX =
            "You are an expert Android reverse engineer. The input is JADX-decompiled Java " +
            "(not source). Reconstruct idiomatic, readable Java. Preserve method and class names. " +
            "You may rename locals for clarity. Return only the Java code, no commentary.";

    private static final String ANDROID_JAVA_SUMMARIZE =
            "You are an expert Android security researcher. Summarise what the supplied " +
            "JADX-decompiled Java method/class does in 2-4 sentences of plain English. Focus on " +
            "purpose, sensitive APIs (WebView, SQLite, SharedPreferences, crypto, IPC), and " +
            "notable frameworks. Format as plain text, no markdown headers.";

    private static final String ANDROID_JAVA_FIND_VULNS =
            "You are an expert Android mobile security auditor analysing ONE JADX-decompiled " +
            "Java method or class (not original source).\n\n" +
            "Detect real security vulnerabilities only: WebView XSS / addJavascriptInterface, " +
            "SQL injection (rawQuery/execSQL), path traversal, insecure SharedPreferences or " +
            "MODE_WORLD_*, exported component / Intent IPC misuse, weak crypto or Keystore misuse, " +
            "cleartext HTTP in code, hardcoded secrets, sensitive Log.* logging, auth bypass. " +
            "Skip style or readability issues. Do NOT treat this as iOS/ObjC/Keychain code.\n\n" +
            JSON_RESPONSE_FORMAT +
            "CRITICAL detection_regex rules — your regex runs against JADX Java text, NOT Ghidra C:\n" +
            "1. Must compile with java.util.regex.Pattern.compile()\n" +
            "2. Statement order matches normal Java (not reversed ObjC msgSend patterns)\n" +
            "3. Match Java APIs and identifiers as they appear (e.g. execSQL, openFileOutput, " +
            "setJavaScriptEnabled, addJavascriptInterface, MODE_WORLD_READABLE)\n" +
            "4. Prefer keyword tokens with generous windows: `[\\s\\S]{0,2000}` between related tokens\n" +
            "5. Your regex MUST match the supplied function's decompiled code (auto-validated; " +
            "non-matching regexes are dropped)\n" +
            "6. Escape regex metacharacters in literals: . ( ) [ ] * + ? { } | ^ $ \\\\\n" +
            "7. Aim 40-300 chars; specific enough to avoid false positives\n\n" +
            "If no real vulnerabilities, output exactly: {\"vulnerabilities\": []}";

    // ── Android native (Ghidra ELF .so) prompts ───────────────────────────────

    private static final String ANDROID_NATIVE_AUTO_FIX =
            "You are an expert Android native reverse engineer. Translate the supplied " +
            "Ghidra-decompiled C/C++ from an Android .so into cleaner, idiomatic C. " +
            "Preserve exported/JNI symbol names. Return only the C code, no commentary.";

    private static final String ANDROID_NATIVE_SUMMARIZE =
            "You are an expert Android native security researcher. Summarise what the supplied " +
            "Ghidra-decompiled native function from an APK .so does in 2-4 sentences. Note JNI " +
            "boundaries, crypto, networking, and unsafe memory operations. Plain text only.";

    private static final String ANDROID_NATIVE_FIND_VULNS =
            "You are an expert Android native security auditor analysing ONE Ghidra-decompiled " +
            "function from an APK native library (.so), not Java source.\n\n" +
            "Detect real issues only: buffer overflows, insecure libc (strcpy/sprintf/gets), " +
            "format-string bugs, weak RNG, hardcoded secrets, JNI trust-boundary flaws, " +
            "command injection via system/popen. Skip style issues.\n\n" +
            JSON_RESPONSE_FORMAT +
            "CRITICAL detection_regex rules — regex runs against Ghidra C-like pseudocode:\n" +
            "1. Must compile with java.util.regex.Pattern.compile()\n" +
            "2. Match C identifiers/APIs as decompiled (strcpy, sprintf, gets, system, etc.)\n" +
            "3. Use generous distance windows `[\\s\\S]{0,2000}` between tokens\n" +
            "4. Regex MUST match the supplied function (auto-validated)\n" +
            "5. Escape regex metacharacters; aim 40-300 chars\n\n" +
            "If no real vulnerabilities, output exactly: {\"vulnerabilities\": []}";

    private final LlmProvider provider;
    private final LlmMode     mode;
    private final LlmCache    cache;
    private final boolean     isSwift;
    private final LearnedRulesStore rulesStore;
    private final PackagePlatform platform;

    public LlmEnricher(LlmProvider provider, LlmMode mode, LlmCache cache, boolean isSwift) {
        this(provider, mode, cache, isSwift, PackagePlatform.IOS);
    }

    public LlmEnricher(LlmProvider provider, LlmMode mode, LlmCache cache, boolean isSwift,
                       PackagePlatform platform) {
        this(provider, mode, cache, isSwift, platform, LearnedRulesStore.forPlatform(platform));
    }

    public LlmEnricher(LlmProvider provider, LlmMode mode, LlmCache cache, boolean isSwift,
                       LearnedRulesStore rulesStore) {
        this(provider, mode, cache, isSwift, PackagePlatform.IOS, rulesStore);
    }

    public LlmEnricher(LlmProvider provider, LlmMode mode, LlmCache cache, boolean isSwift,
                       PackagePlatform platform, LearnedRulesStore rulesStore) {
        this.provider   = provider;
        this.mode       = mode;
        this.cache      = cache;
        this.isSwift    = isSwift;
        this.platform   = platform == null ? PackagePlatform.IOS : platform;
        this.rulesStore = rulesStore != null ? rulesStore : LearnedRulesStore.forPlatform(this.platform);
    }

    public void enrich(SqliteStore store, String executableName) {
        List<SqliteStore.DecompilationResult> fns = store.getAllDecompiledFunctions(executableName);
        log.info("LLM enrichment: mode={} platform={} provider={} functions={}",
                mode, platform, provider.getClass().getSimpleName(), fns.size());

        int cached = 0, called = 0, errors = 0, totalVulns = 0, newRules = 0;

        for (SqliteStore.DecompilationResult fn : fns) {
            if (fn.decompiledCode() == null || fn.decompiledCode().isBlank()) continue;

            String origin = resolveOrigin(fn);
            String systemPrompt = buildSystemPrompt(origin);
            String userMessage = buildUserMessage(fn, origin);
            String hash = cacheKey(fn.decompiledCode(), mode, platform, origin);

            String finding = cache.get(hash).orElse(null);
            if (finding != null) {
                cached++;
            } else {
                try {
                    finding = provider.complete(systemPrompt, userMessage);
                    cache.put(hash, finding);
                    called++;
                } catch (LlmProvider.LlmException e) {
                    log.warn("LLM call failed for {}.{}: {}", fn.className(), fn.functionName(), e.getMessage());
                    errors++;
                    continue;
                }
            }

            store.insertLlmFinding(fn.functionName(), fn.className(), executableName,
                    mode.name(), finding, hash);

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
            String description  = sanitizeLlmText(optString(v, "description", ""));
            String evidence     = sanitizeLlmText(optString(v, "evidence", ""));
            String pocSteps     = sanitizeLlmText(optString(v, "poc_steps", ""));
            String remediation  = sanitizeLlmText(optString(v, "remediation", ""));
            String detectionRe  = optString(v, "detection_regex", "");

            // Skip hollow findings: title alone with only ellipsis placeholders is noise.
            if (LearnedRulesStore.isPlaceholderText(title)
                    || (description.isBlank() && evidence.isBlank() && pocSteps.isBlank())) {
                log.info("Skipping incomplete LLM finding for {}.{} (scope={}): {}",
                        fn.className(), fn.functionName(), scope, title);
                continue;
            }

            String category = scopeToCategory(scope);
            String functionLocation = (fn.className() == null ? "" : fn.className() + ".") + fn.functionName();
            String referenceUrl = "LLM-discovered " + java.time.LocalDate.now() +
                                  " from function " + functionLocation;

            String ruleId = null;
            String validationStatus = "MISSING_REGEX";
            if (LearnedRulesStore.isUsableDetectionRegex(detectionRe)) {
                if (regexMatchesSource(detectionRe, fn.decompiledCode())) {
                    ruleId = rulesStore.addRule(
                            scope, title, category, severity, cvss, cwe,
                            description, remediation,
                            "DECOMPILED", detectionRe,
                            pocSteps, referenceUrl, platform.name());
                    validationStatus = ruleId != null ? "OK" : "INVALID_REGEX";
                } else {
                    validationStatus = "REGEX_FAILED_SELF_TEST";
                    log.info("Dropping non-matching regex for {}.{} (scope={}): {}",
                            fn.className(), fn.functionName(), scope,
                            detectionRe.length() > 100 ? detectionRe.substring(0, 100) + "…" : detectionRe);
                }
            } else if (!detectionRe.isBlank()) {
                validationStatus = "PLACEHOLDER_REGEX";
                log.info("Dropping placeholder/low-quality regex for {}.{} (scope={}): {}",
                        fn.className(), fn.functionName(), scope,
                        detectionRe.length() > 100 ? detectionRe.substring(0, 100) + "…" : detectionRe);
            }
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

    /** Collapse LLM ellipsis/stub fields to empty so the UI does not render "{@code ...}". */
    static String sanitizeLlmText(String s) {
        if (s == null || LearnedRulesStore.isPlaceholderText(s)) return "";
        return s;
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
            case "XSS", "INJECTION", "PATH-TRAVERSAL", "INPUT-VALIDATION", "MEMORY-SAFETY",
                 "SQL-INJECTION", "JNI"
                    -> "CODE";
            case "KEYCHAIN", "INSECURE-STORAGE", "INSECURE-LOG", "IPC", "KEYSTORE"
                    -> "STORAGE";
            case "CRYPTO"   -> "CRYPTO";
            case "AUTH"     -> "AUTH";
            case "NETWORK", "CLEARTEXT" -> "NETWORK";
            case "WEBVIEW", "URLSCHEME", "EXPORTED-COMPONENT" -> "PLATFORM";
            case "DEBUG"    -> "RESILIENCE";
            default         -> "CODE";
        };
    }

    private static boolean regexMatchesSource(String regex, String sourceCode) {
        if (regex == null || sourceCode == null) return false;
        try {
            return java.util.regex.Pattern.compile(regex).matcher(sourceCode).find();
        } catch (java.util.regex.PatternSyntaxException ex) {
            return false;
        }
    }

    static JsonObject extractVulnsJson(String raw) {
        if (raw == null || raw.isBlank()) return null;

        String text = raw.trim();

        JsonObject direct = tryParseVulnsObject(stripCodeFences(text));
        if (direct != null) return direct;

        int searchFrom = 0;
        while (true) {
            int fence = indexOfIgnoreCase(text, "```", searchFrom);
            if (fence < 0) break;
            int afterOpen = fence + 3;
            int nl = text.indexOf('\n', afterOpen);
            if (nl < 0) break;
            int close = text.indexOf("```", nl + 1);
            if (close < 0) break;
            JsonObject fromFence = tryParseVulnsObject(text.substring(nl + 1, close).trim());
            if (fromFence != null) return fromFence;
            searchFrom = close + 3;
        }

        int idx = lastIndexOfVulnsObject(text);
        if (idx >= 0) {
            String candidate = extractBalancedOrRepair(text, idx);
            JsonObject embedded = tryParseVulnsObject(candidate);
            if (embedded != null) return embedded;
        }

        return null;
    }

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

    private static int lastIndexOfVulnsObject(String text) {
        int best = -1;
        int from = 0;
        while (from < text.length()) {
            int key = text.indexOf("\"vulnerabilities\"", from);
            if (key < 0) break;
            int i = key - 1;
            while (i >= 0 && Character.isWhitespace(text.charAt(i))) i--;
            if (i >= 0 && text.charAt(i) == '{') best = i;
            from = key + 1;
        }
        return best;
    }

    private static String extractBalancedOrRepair(String text, int start) {
        if (start < 0 || start >= text.length() || text.charAt(start) != '{') return null;

        String balanced = extractBalanced(text, start);
        if (balanced != null) return balanced;

        return repairTruncatedJson(text.substring(start));
    }

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
            if (obj == null) break;
            if (!entries.isEmpty()) entries.append(',');
            entries.append(obj);
            i += obj.length();
        }
        return "{\"vulnerabilities\":[" + entries + "]}";
    }

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

    // ── prompt / envelope helpers (package-visible for tests) ─────────────────

    static String resolveOrigin(SqliteStore.DecompilationResult fn) {
        if (fn == null) return "GHIDRA";
        String o = fn.resolvedOrigin();
        if ("JADX".equals(o)) return "JADX";
        // ParentClass convention for Android native libs: native:libfoo.so
        String cls = fn.className();
        if (cls != null && cls.startsWith("native:")) return "GHIDRA";
        return o;
    }

    String buildSystemPrompt(String origin) {
        boolean android = platform == PackagePlatform.ANDROID;
        boolean nativeElf = android && "GHIDRA".equalsIgnoreCase(origin);

        if (!android) {
            return switch (mode) {
                case AUTO_FIX -> String.format(IOS_AUTO_FIX, isSwift ? "Swift" : "Objective-C");
                case SUMMARIZE -> IOS_SUMMARIZE;
                case FIND_VULNS -> IOS_FIND_VULNS;
            };
        }
        if (nativeElf) {
            return switch (mode) {
                case AUTO_FIX -> ANDROID_NATIVE_AUTO_FIX;
                case SUMMARIZE -> ANDROID_NATIVE_SUMMARIZE;
                case FIND_VULNS -> ANDROID_NATIVE_FIND_VULNS;
            };
        }
        return switch (mode) {
            case AUTO_FIX -> ANDROID_JAVA_AUTO_FIX;
            case SUMMARIZE -> ANDROID_JAVA_SUMMARIZE;
            case FIND_VULNS -> ANDROID_JAVA_FIND_VULNS;
        };
    }

    String buildUserMessage(SqliteStore.DecompilationResult fn, String origin) {
        String decompiler = "JADX".equalsIgnoreCase(origin) ? "JADX" : "GHIDRA";
        String language = languageHint(origin);
        String cls = fn.className() == null ? "" : fn.className();
        String name = fn.functionName() == null ? "" : fn.functionName();
        String fenceLang = "JADX".equalsIgnoreCase(origin) ? "java" : "c";
        return """
                platform: %s
                decompiler: %s
                language_hint: %s
                class: %s
                function: %s

                ```%s
                %s
                ```
                """.formatted(platform.name(), decompiler, language, cls, name, fenceLang,
                fn.decompiledCode() == null ? "" : fn.decompiledCode());
    }

    private String languageHint(String origin) {
        if (platform == PackagePlatform.ANDROID) {
            return "JADX".equalsIgnoreCase(origin) ? "Java" : "C";
        }
        return isSwift ? "Swift" : "Objective-C/C";
    }

    static String cacheKey(String code, LlmMode mode, PackagePlatform platform, String origin) {
        String plat = platform == null ? "IOS" : platform.name();
        String org = origin == null || origin.isBlank() ? "GHIDRA" : origin.toUpperCase();
        return sha256(code + "|" + mode.name() + "|" + plat + "|" + org + "|" + PROMPT_VERSION);
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
