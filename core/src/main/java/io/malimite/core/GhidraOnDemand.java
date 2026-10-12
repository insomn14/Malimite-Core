package io.malimite.core;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * On-demand Ghidra decompile of single functions without re-running the whole-binary scan.
 *
 * <p>The scan deletes its Ghidra project ({@code -deleteProject}), so the first request per binary
 * re-extracts it from the original package and imports + analyzes it into a <em>persistent</em>
 * project under {@code <scan-dir>/ghidra-proj/<key>} (minutes). Later requests only reopen that
 * project with {@code -process -noanalysis -readOnly} and run {@code DecompileOne.java} (JVM + project
 * open cost). The scan path ({@link GhidraRunner}) is untouched.
 */
public final class GhidraOnDemand {

    private static final Logger log = LoggerFactory.getLogger(GhidraOnDemand.class);
    private static final long IMPORT_TIMEOUT_MIN = 60;
    private static final long PROCESS_TIMEOUT_MIN = 15;
    private static final int MAX_MATCHES = 3;
    private static final String MARKER = ".imported";

    private GhidraOnDemand() {}

    /** @param lib Android native lib file name (e.g. libfoo.so); ignored for iOS. */
    public static String decompile(Path scanDir, JSONObject meta, Path pkg, String query, String lib) throws Exception {
        CoreConfig cfg = CoreConfig.fromEnv(null);
        boolean android = "ANDROID".equalsIgnoreCase(meta.optString("platform"));
        String key = projectKey(android ? lib : "main");
        Path root = scanDir.resolve("ghidra-proj");
        Files.createDirectories(root);
        Path projDir = root.resolve(key);
        String projName = key + "_ondemand";

        // one request per binary at a time (also across processes): a second first-time call would
        // otherwise delete the project the first one is still importing
        try (var ch = java.nio.channels.FileChannel.open(root.resolve(key + ".lock"),
                java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.WRITE);
             var lock = ch.tryLock()) {
            if (lock == null)
                throw new IOException("another Ghidra request for this binary is running (first import can take minutes); retry shortly");
            return decompileLocked(cfg, meta, pkg, query, lib, android, projDir, projName);
        }
    }

    /** Sanitised name plus a hash, so distinct lib names can never collide on the same project dir. */
    static String projectKey(String name) {
        return GhidraRunner.sanitizeProjectName(name) + "-" + Integer.toHexString(name.hashCode());
    }

    private static String decompileLocked(CoreConfig cfg, JSONObject meta, Path pkg, String query, String lib,
                                          boolean android, Path projDir, String projName) throws Exception {
        String program = readMarker(projDir);
        if (program == null) {
            program = importProject(cfg, meta, pkg, android, lib, projDir, projName);
        }

        Path scriptDir = Files.createTempDirectory("malimite-ghidra1-");
        try {
            try (InputStream in = GhidraOnDemand.class.getResourceAsStream("/ghidra/DecompileOne.java")) {
                if (in == null) throw new IllegalStateException("DecompileOne.java missing from classpath resources");
                Files.copy(in, scriptDir.resolve("DecompileOne.java"), StandardCopyOption.REPLACE_EXISTING);
            }
            Path outFile = scriptDir.resolve("out.txt");
            run(processCmd(cfg, projDir, projName, program, scriptDir, outFile, query), PROCESS_TIMEOUT_MIN, "ghidra process");
            if (!Files.isRegularFile(outFile))
                return "";  // script ran but nothing matched (caller turns this into a helpful message)
            return Files.readString(outFile, StandardCharsets.UTF_8);
        } finally {
            OnDemandDecompiler.deleteTree(scriptDir);
        }
    }

    private static String importProject(CoreConfig cfg, JSONObject meta, Path pkg, boolean android, String lib,
                                        Path projDir, String projName) throws Exception {
        OnDemandDecompiler.deleteTree(projDir);  // leftover from an interrupted import: no marker => not trusted
        Files.createDirectories(projDir);
        Path work = Files.createTempDirectory("malimite-ghidra-src-");
        try {
            Path binary;
            if (android) {
                var ex = ApkExtractor.extract(pkg, work);
                binary = ApkExtractor.preferArm64NativeLibs(ex.nativeLibs()).stream()
                        .filter(p -> p.getFileName().toString().equals(lib)).findFirst()
                        .orElseThrow(() -> new IllegalArgumentException("native lib '" + lib + "' not found in arm64-v8a; available: "
                                + ApkExtractor.preferArm64NativeLibs(ex.nativeLibs()).stream()
                                        .map(p -> p.getFileName().toString()).toList()));
            } else {
                var ex = IpaExtractor.extract(pkg, work);
                binary = ex.executablePath();
                Macho macho = new Macho(binary.toString(), work.toString(), ex.executableName());
                if (macho.isUniversalBinary()) {  // same arch choice as the scan, so addresses/names match
                    List<String> archs = macho.getArchitectureStrings();
                    macho.processUniversalMacho(archs.stream().filter(a -> a.contains("ARM64")).findFirst().orElse(archs.get(0)));
                }
            }
            log.info("Ghidra on-demand: importing + analyzing {} (first request for this scan; may take minutes)", binary);
            try {
                run(importCmd(cfg, projDir, projName, binary), IMPORT_TIMEOUT_MIN, "ghidra import");
            } catch (Exception e) {
                OnDemandDecompiler.deleteTree(projDir);  // never keep a half-built project
                throw e;
            }
            String program = binary.getFileName().toString();
            Files.writeString(projDir.resolve(MARKER), program, StandardCharsets.UTF_8);
            return program;
        } finally {
            OnDemandDecompiler.deleteTree(work);
        }
    }

    static String readMarker(Path projDir) throws IOException {
        Path m = projDir.resolve(MARKER);
        if (!Files.isRegularFile(m)) return null;
        String s = Files.readString(m, StandardCharsets.UTF_8).strip();
        return s.isEmpty() ? null : s;
    }

    /**
     * Plain import + default auto-analysis, no analyzer flags: headless has no -enableAnalyzer/-skipAnalysisPrompt
     * (12.x reads them as extra import paths, 11.x rejects them). GhidraRunner passes them after -postScript where
     * they are swallowed as script arguments, so the scan runs with the default analyzers too: same analysis here.
     * No -deleteProject: this project is kept.
     */
    static List<String> importCmd(CoreConfig cfg, Path projDir, String projName, Path binary) {
        return List.of(cfg.analyzeHeadlessPath().toString(), projDir.toString(), projName, "-import", binary.toString());
    }

    static List<String> processCmd(CoreConfig cfg, Path projDir, String projName, String program,
                                   Path scriptDir, Path outFile, String query) {
        return List.of(cfg.analyzeHeadlessPath().toString(), projDir.toString(), projName,
                "-process", program, "-noanalysis", "-readOnly",
                "-scriptPath", scriptDir.toString(),
                "-postScript", "DecompileOne.java", outFile.toString(), query, String.valueOf(MAX_MATCHES));
    }

    /** The meaningful failure lines of a headless run: no stack frames, no log4j hostname noise. */
    static String summarizeFailure(java.util.Collection<String> lines) {
        List<String> key = new ArrayList<>();
        String lastPlain = "";
        for (String l : lines) {
            String t = l.strip();
            if (t.isEmpty() || t.startsWith("at ") || t.startsWith("... ") || t.startsWith("Caused by")
                    || t.contains("Could not determine local host name")
                    || t.contains("UnknownHostException")) continue;   // log4j noise when the sandbox has no DNS
            lastPlain = t;
            if (t.contains("Bad argument") || t.contains("Abort") || t.contains("ERROR") || t.contains("Exception"))
                key.add(t.length() > 300 ? t.substring(0, 300) : t);
        }
        if (key.isEmpty()) return lastPlain;
        return String.join(" | ", key.subList(Math.max(0, key.size() - 3), key.size()));
    }

    private static void run(List<String> cmd, long timeoutMin, String what) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(cmd).redirectErrorStream(true);
        Path jh = GhidraRunner.resolveGhidraJavaHome();
        if (jh != null) {
            pb.environment().put("JAVA_HOME", jh.toString());
            pb.environment().remove("JDK_HOME");
        }
        log.info("Running {}: {}", what, String.join(" ", cmd));
        Process p = pb.start();
        Deque<String> tail = new ArrayDeque<>();
        Thread reader = new Thread(() -> {
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) {
                    synchronized (tail) { tail.addLast(line); if (tail.size() > 400) tail.removeFirst(); }
                }
            } catch (IOException ignored) { /* process ended */ }
        });
        reader.setDaemon(true);
        reader.start();
        if (!p.waitFor(timeoutMin, TimeUnit.MINUTES)) {
            p.descendants().forEach(ProcessHandle::destroyForcibly);  // analyzeHeadless spawns the real Ghidra JVM
            p.destroyForcibly();
            throw new IOException(what + " timed out after " + timeoutMin + " minutes");
        }
        reader.join(2000);
        if (p.exitValue() != 0) {
            String errs;
            synchronized (tail) { errs = summarizeFailure(tail); }
            throw new IOException(what + " failed (exit=" + p.exitValue() + "): " + errs);
        }
    }
}
