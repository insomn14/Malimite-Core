package io.malimite.core;

import com.google.gson.Gson;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Ingests JADX Java sources into the existing {@link SqliteStore} schema
 * (Classes / Functions / MachoStrings / EntryPoints / ResourceStrings).
 *
 * <p>Does not apply {@link ScanScope}: third-party app dependencies (RootBeer,
 * RASP, pinning SDKs, ObjectBox, …) stay in the store so {@link AssessmentScanner}
 * can inventory them. First-party filtering happens later in
 * {@link VulnerabilityScanner}, {@link LlmEnricher}, and native Ghidra.
 */
public final class JadxIngest {

    private static final Logger log = LoggerFactory.getLogger(JadxIngest.class);
    private static final Gson GSON = new Gson();
    private static final Pattern PACKAGE = Pattern.compile("(?m)^\\s*package\\s+([\\w.]+)\\s*;");
    /**
     * Heuristic method start for JADX Java output.
     * Possessive modifier group ({@code *+}) and bounded param/throws spans avoid
     * catastrophic backtracking (StackOverflowError) on truncated/synthetic sources.
     */
    private static final Pattern METHOD_START = Pattern.compile(
            "(?m)^[ \\t]*"
                    + "(?:(?:public|protected|private|static|final|native|synchronized|abstract|default|strictfp)[ \\t]++)*+"
                    + "(?:<[^>\\n]{1,200}>[ \\t]+)?"
                    + "[\\w.<>\\[\\]?]+[ \\t]+"
                    + "([\\w$]+)\\s*\\([^;\\n]{0,2000}\\)\\s*(?:throws[^{\\n]{0,500})?\\{");
    private static final int MAX_STRINGS = 50_000;
    private static final int MAX_FILE_CHARS = 200_000;
    /** Skip method splitting on large files — regex scan is O(n) and low-value past this. */
    private static final int MAX_METHOD_SPLIT_CHARS = 80_000;
    private static final int MAX_METHODS_PER_CLASS = 200;
    /** Cap per-literal scan length — long / unclosed literals used to StackOverflow the regex engine. */
    private static final int MAX_STRING_LIT_CHARS = 2_000;

    private JadxIngest() {}

    public static void ingest(
            Path sourcesRoot,
            SqliteStore store,
            String executableName,
            AndroidManifestParser.ManifestInfo manifest,
            ApkExtractor.ExtractionResult extraction) throws IOException {

        Map<String, List<String>> classFns = new HashMap<>();
        List<SqliteStore.DecompilationResult> batch = new ArrayList<>();
        int stringIdx = 0;
        int skipped = 0;
        int ingested = 0;

        try (var walk = Files.walk(sourcesRoot)) {
            List<Path> javaFiles = walk
                    .filter(Files::isRegularFile)
                    .filter(p -> p.toString().endsWith(".java"))
                    .toList();

            for (Path javaFile : javaFiles) {
                try {
                    String fqcn = toFqcn(sourcesRoot, javaFile);
                    if (AndroidLibraryDefinitions.shouldSkip(fqcn)) {
                        skipped++;
                        continue;
                    }
                    stringIdx = ingestJavaFile(
                            javaFile, fqcn, store, executableName,
                            classFns, batch, stringIdx);
                    ingested++;
                    if (batch.size() >= 100) {
                        store.insertFunctionDecompilations(batch);
                        batch.clear();
                    }
                } catch (StackOverflowError e) {
                    // Error, not Exception — must not kill the JVM mid-scan.
                    log.warn("JADX ingest StackOverflowError on {} — skipping file", javaFile.getFileName());
                } catch (VirtualMachineError e) {
                    throw e;
                } catch (Error e) {
                    log.warn("JADX ingest Error ({}) on {} — skipping file",
                            e.getClass().getSimpleName(), javaFile.getFileName());
                } catch (Exception e) {
                    log.warn("JADX ingest skip {}: {}", javaFile.getFileName(), e.getMessage());
                }
            }
        }

        if (!batch.isEmpty())
            store.insertFunctionDecompilations(batch);

        for (var e : classFns.entrySet())
            store.insertClass(e.getKey(), GSON.toJson(e.getValue()), executableName);

        ingestManifest(store, executableName, manifest);
        ingestResources(store, extraction);

        log.info("JADX ingest: classes={} skippedLibs={} strings={}", ingested, skipped, stringIdx);
    }

    /**
     * Ingest one JADX .java file. Returns the updated string index.
     * String literals are extracted with a linear scanner — never {@code Pattern} —
     * because {@code "((?:\\\\.|[^\"\\\\])*)"} StackOverflows on truncated / long sources.
     */
    private static int ingestJavaFile(
            Path javaFile,
            String fqcn,
            SqliteStore store,
            String executableName,
            Map<String, List<String>> classFns,
            List<SqliteStore.DecompilationResult> batch,
            int stringIdx) throws IOException {

        String code = Files.readString(javaFile, StandardCharsets.UTF_8);
        boolean truncated = code.length() > MAX_FILE_CHARS;
        if (truncated)
            code = code.substring(0, MAX_FILE_CHARS) + "\n/* truncated */\n";

        String classSimple = fqcn.contains(".")
                ? fqcn.substring(fqcn.lastIndexOf('.') + 1)
                : fqcn;

        List<String> methodNames = new ArrayList<>();
        methodNames.add("<class>");
        batch.add(new SqliteStore.DecompilationResult(
                "<class>", fqcn, code, executableName, "JADX"));

        if (!isLowValueGenerated(classSimple) && !truncated
                && code.length() <= MAX_METHOD_SPLIT_CHARS) {
            for (MethodSlice slice : splitMethods(code)) {
                methodNames.add(slice.name());
                batch.add(new SqliteStore.DecompilationResult(
                        slice.name(), fqcn, slice.body(), executableName, "JADX"));
            }
        }
        classFns.put(fqcn, methodNames);

        for (String lit : extractStringLiterals(code, MAX_STRINGS - stringIdx)) {
            if (stringIdx >= MAX_STRINGS) break;
            store.insertMachoString(
                    "jadx:" + stringIdx,
                    lit,
                    "__JADX",
                    classSimple,
                    executableName);
            stringIdx++;
        }
        return stringIdx;
    }

    /**
     * Linear Java string-literal extractor (no regex). Skips unclosed / oversized literals.
     * Returns unescaped contents with length in {@code [4, 500]}.
     */
    static List<String> extractStringLiterals(String code, int maxResults) {
        List<String> out = new ArrayList<>();
        if (code == null || maxResults <= 0) return out;
        int n = code.length();
        for (int i = 0; i < n && out.size() < maxResults; i++) {
            char c = code.charAt(i);
            if (c == '"' && !isTextBlockOpen(code, i)) {
                int start = i + 1;
                int j = start;
                boolean closed = false;
                while (j < n && j - start <= MAX_STRING_LIT_CHARS) {
                    char ch = code.charAt(j);
                    if (ch == '\\') {
                        if (j + 1 >= n) break; // truncated escape
                        j += 2;
                        continue;
                    }
                    if (ch == '"') {
                        closed = true;
                        break;
                    }
                    if (ch == '\n' || ch == '\r') break; // unclosed / truncated
                    j++;
                }
                if (closed) {
                    String raw = code.substring(start, Math.min(j, n));
                    String lit = unescape(raw);
                    if (lit.length() >= 4 && lit.length() <= 500)
                        out.add(lit);
                    i = j; // continue after closing quote
                } else {
                    i = Math.min(j, n) - 1; // skip past abandoned span
                }
            }
        }
        return out;
    }

    /** True when {@code code[i]} starts a Java text block {@code """}. */
    private static boolean isTextBlockOpen(String code, int i) {
        return i + 2 < code.length()
                && code.charAt(i + 1) == '"'
                && code.charAt(i + 2) == '"';
    }

    record MethodSlice(String name, String body) {}

    /** Split JADX Java into method bodies; empty if none detected or on regex failure. */
    static List<MethodSlice> splitMethods(String code) {
        try {
            return splitMethodsUnsafe(code);
        } catch (StackOverflowError e) {
            log.warn("JADX method split StackOverflowError — keeping class body only");
            return List.of();
        } catch (VirtualMachineError e) {
            throw e; // OOM / InternalError — do not continue
        } catch (Error e) {
            // One pathological file must not abort the whole ingest.
            log.warn("JADX method split Error ({}) — keeping class body only", e.getClass().getSimpleName());
            return List.of();
        }
    }

    private static List<MethodSlice> splitMethodsUnsafe(String code) {
        List<MethodSlice> out = new ArrayList<>();
        Matcher m = METHOD_START.matcher(code);
        List<int[]> starts = new ArrayList<>();
        List<String> names = new ArrayList<>();
        while (m.find() && starts.size() < MAX_METHODS_PER_CLASS) {
            String name = m.group(1);
            if ("if".equals(name) || "for".equals(name) || "while".equals(name)
                    || "switch".equals(name) || "catch".equals(name) || "synchronized".equals(name))
                continue;
            starts.add(new int[]{m.start(), m.end() - 1}); // index of '{'
            names.add(name);
        }
        for (int i = 0; i < starts.size(); i++) {
            int brace = starts.get(i)[1];
            int end = findMatchingBrace(code, brace);
            if (end < 0) end = Math.min(code.length(), brace + 4_000);
            String body = code.substring(starts.get(i)[0], Math.min(code.length(), end + 1));
            if (body.length() > MAX_FILE_CHARS / 2)
                body = body.substring(0, MAX_FILE_CHARS / 2) + "\n/* truncated */\n";
            out.add(new MethodSlice(names.get(i), body));
        }
        return out;
    }

    /** R.java / R$*.java / BuildConfig — huge or low-signal for method-level rules. */
    static boolean isLowValueGenerated(String classSimple) {
        return "R".equals(classSimple)
                || (classSimple != null && classSimple.startsWith("R$"))
                || "BuildConfig".equals(classSimple);
    }

    private static int findMatchingBrace(String code, int openIdx) {
        int depth = 0;
        boolean inStr = false, inChar = false, inLine = false, inBlock = false;
        for (int i = openIdx; i < code.length(); i++) {
            char c = code.charAt(i);
            char prev = i > 0 ? code.charAt(i - 1) : 0;
            if (inLine) {
                if (c == '\n') inLine = false;
                continue;
            }
            if (inBlock) {
                if (prev == '*' && c == '/') inBlock = false;
                continue;
            }
            if (inStr) {
                if (c == '"' && prev != '\\') inStr = false;
                continue;
            }
            if (inChar) {
                if (c == '\'' && prev != '\\') inChar = false;
                continue;
            }
            if (c == '/' && i + 1 < code.length()) {
                char n = code.charAt(i + 1);
                if (n == '/') { inLine = true; i++; continue; }
                if (n == '*') { inBlock = true; i++; continue; }
            }
            if (c == '"') { inStr = true; continue; }
            if (c == '\'') { inChar = true; continue; }
            if (c == '{') depth++;
            else if (c == '}') {
                depth--;
                if (depth == 0) return i;
            }
        }
        return -1;
    }

    private static void ingestManifest(
            SqliteStore store, String executableName, AndroidManifestParser.ManifestInfo m) {
        if (m == null) return;
        store.insertResourceString("PackageName", "PackageName=" + nullToEmpty(m.packageName()), "manifest");
        if (m.minSdk() != null)
            store.insertResourceString("MinSdk", "MinSdk=" + m.minSdk(), "manifest");
        if (m.targetSdk() != null)
            store.insertResourceString("TargetSdk", "TargetSdk=" + m.targetSdk(), "manifest");
        store.insertResourceString("Debuggable", "Debuggable=" + (m.debuggable() ? "true" : "false"), "manifest");
        boolean allowBackup = m.allowBackup() != null
                ? m.allowBackup()
                : (m.targetSdk() == null || m.targetSdk() < 31);
        store.insertResourceString("AllowBackup", "AllowBackup=" + (allowBackup ? "true" : "false"), "manifest");
        if (m.usesCleartextTraffic() != null)
            store.insertResourceString("UsesCleartextTraffic",
                    "UsesCleartextTraffic=" + (m.usesCleartextTraffic() ? "true" : "false"), "manifest");
        if (m.networkSecurityConfig() != null)
            store.insertResourceString("NetworkSecurityConfig",
                    "NetworkSecurityConfig=" + m.networkSecurityConfig(), "manifest");

        for (String perm : m.permissions())
            store.insertResourceString("Permission", "Permission=" + perm, "manifest-permission");

        for (var c : m.components()) {
            String flag = c.exported() ? "exported=true" : "exported=false";
            String perm = c.permission() != null ? " permission=" + c.permission() : "";
            store.insertResourceString(
                    "Component",
                    c.type() + " " + c.name() + " " + flag + perm,
                    "manifest-component");
            // Skip library exported components as entry points
            String compFqcn = normalizeComponentName(m.packageName(), c.name());
            if (c.exported() && !AndroidLibraryDefinitions.shouldSkip(compFqcn))
                store.insertEntryPoint(c.type() + ":" + c.name(), c.name(), executableName);
        }

        for (var link : m.deepLinks()) {
            store.insertResourceString("DeepLink",
                    "DeepLink scheme=" + nullToEmpty(link.scheme())
                            + " host=" + nullToEmpty(link.host())
                            + " path=" + nullToEmpty(link.pathPrefix())
                            + " component=" + nullToEmpty(link.component()),
                    "manifest-deeplink");
        }
    }

    private static void ingestResources(SqliteStore store, ApkExtractor.ExtractionResult extraction)
            throws IOException {
        if (extraction == null) return;
        if (extraction.nativeLibs() != null) {
            for (Path so : extraction.nativeLibs())
                store.insertResourceString("NativeLib", so.toString(), "native-lib");
        }
        if (extraction.assetsDir() != null) {
            try (var walk = Files.walk(extraction.assetsDir())) {
                walk.filter(Files::isRegularFile).limit(200).forEach(p ->
                        store.insertResourceString("AssetPath",
                                extraction.rootDir().relativize(p).toString(), "asset"));
            }
        }
        if (extraction.resDir() != null) {
            try (var walk = Files.walk(extraction.resDir())) {
                walk.filter(p -> {
                    String n = p.getFileName().toString().toLowerCase();
                    return n.endsWith(".xml") || n.endsWith(".json");
                }).limit(300).forEach(p -> {
                    try {
                        String body = Files.readString(p, StandardCharsets.UTF_8);
                        if (body.length() > 8_000) body = body.substring(0, 8_000);
                        String rel = extraction.rootDir().relativize(p).toString();
                        store.insertResourceString(rel, body, "res-xml");
                        // Network security config snippets for RESOURCES rules
                        if (rel.contains("network_security") || body.contains("network-security-config")
                                || body.contains("pin-set") || body.contains("cleartextTrafficPermitted")) {
                            ingestNscSnippets(store, body);
                        }
                    } catch (Exception ignored) {}
                });
            }
        }
    }

    /** Flatten NSC XML into searchable ResourceStrings. */
    static void ingestNscSnippets(SqliteStore store, String xml) {
        if (xml == null || xml.isBlank()) return;
        store.insertResourceString("NSC", "NSC=" + xml.replaceAll("\\s+", " ").trim(), "nsc");
        if (xml.matches("(?is).*cleartextTrafficPermitted\\s*=\\s*\"true\".*"))
            store.insertResourceString("NSC", "NSC=cleartextTrafficPermitted=true", "nsc");
        if (xml.matches("(?is).*cleartextTrafficPermitted\\s*=\\s*\"false\".*"))
            store.insertResourceString("NSC", "NSC=cleartextTrafficPermitted=false", "nsc");
        if (xml.contains("pin-set") || xml.contains("<pin "))
            store.insertResourceString("NSC", "NSC=pin-set-present", "nsc");
        else
            store.insertResourceString("NSC", "NSC=pin-set-absent", "nsc");
        if (xml.matches("(?is).*trust-anchors[^>]*>[^<]*<certificates[^>]*src\\s*=\\s*\"user\".*")
                || xml.matches("(?is).*src\\s*=\\s*\"user\".*"))
            store.insertResourceString("NSC", "NSC=trust-anchors-user", "nsc");
        if (xml.matches("(?is).*expiration[^>]*=\\s*\"[^\"]+\".*"))
            store.insertResourceString("NSC", "NSC=pin-expiration=" + extractAttr(xml, "expiration"), "nsc");
    }

    private static String extractAttr(String xml, String attr) {
        Matcher m = Pattern.compile(attr + "\\s*=\\s*\"([^\"]+)\"").matcher(xml);
        return m.find() ? m.group(1) : "";
    }

    private static String normalizeComponentName(String pkg, String name) {
        if (name == null) return "";
        if (name.startsWith(".")) return (pkg == null ? "" : pkg) + name;
        if (!name.contains(".") && pkg != null) return pkg + "." + name;
        return name;
    }

    private static String toFqcn(Path sourcesRoot, Path javaFile) {
        Path rel = sourcesRoot.relativize(javaFile);
        String s = rel.toString().replace('\\', '/');
        if (s.endsWith(".java")) s = s.substring(0, s.length() - 5);
        try {
            String head = Files.readString(javaFile, StandardCharsets.UTF_8);
            if (head.length() > 2000) head = head.substring(0, 2000);
            Matcher pm = PACKAGE.matcher(head);
            if (pm.find()) {
                String pkg = pm.group(1);
                String simple = javaFile.getFileName().toString().replace(".java", "");
                return pkg + "." + simple;
            }
        } catch (Exception ignored) {}
        return s.replace('/', '.');
    }

    private static String unescape(String s) {
        return s.replace("\\n", "\n").replace("\\t", "\t").replace("\\\"", "\"").replace("\\\\", "\\");
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }
}
