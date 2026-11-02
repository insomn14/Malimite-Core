package io.malimite.core;

import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

/**
 * Runs Ghidra headless analysis on a Mach-O (iOS) or ELF {@code .so} (Android native)
 * binary and ingests results into SqliteStore.
 *
 * Port of Malimite's GhidraProject.java:
 *  - Swing/GUI removed; progress logged via SLF4J
 *  - DumpClassData.java extracted from classpath resources at runtime
 *  - CoreConfig replaces Config
 *  - SqliteStore replaces SQLiteDBHandler
 */
public class GhidraRunner {

    private static final Logger log = LoggerFactory.getLogger(GhidraRunner.class);
    private static final int BASE_PORT        = 8765;
    private static final int MAX_PORT_TRIES   = 10;

    private final String       ghidraProjectName;
    private final CoreConfig   config;
    private final SqliteStore  store;
    private final Path         scriptDir;    // temp dir holding DumpClassData.java
    /** Recent Ghidra ERROR / SCRIPT ERROR lines for better failure messages. */
    private final ConcurrentLinkedDeque<String> ghidraErrors = new ConcurrentLinkedDeque<>();

    public GhidraRunner(String executableBaseName, CoreConfig config, SqliteStore store) throws IOException {
        // Ghidra project names with spaces/special chars break headless arg parsing on some versions
        this.ghidraProjectName = sanitizeProjectName(executableBaseName) + "_malimite";
        this.config            = config;
        this.store             = store;
        this.scriptDir         = extractScriptToTemp();
    }

    /** Keep only filesystem-/Ghidra-safe characters in the headless project name. */
    static String sanitizeProjectName(String executableBaseName) {
        if (executableBaseName == null || executableBaseName.isBlank()) return "binary";
        String cleaned = executableBaseName.replaceAll("[^A-Za-z0-9._-]+", "_");
        cleaned = cleaned.replaceAll("^_+|_+$", "");
        return cleaned.isBlank() ? "binary" : cleaned;
    }

    // ── public API ────────────────────────────────────────────────────────────

    /** iOS Mach-O convenience overload. */
    public void decompile(String executableFilePath, String projectDirectoryPath, Macho macho) {
        List<String> activeLibs = LibraryDefinitions.getActiveLibraries(config);
        decompile(executableFilePath, projectDirectoryPath, BinaryIdentity.fromMacho(macho, activeLibs));
    }

    public void decompile(String executableFilePath, String projectDirectoryPath, BinaryIdentity identity) {
        boolean objcAnalyzer = identity.enableObjectiveCAnalyzer();
        try {
            runOnce(executableFilePath, projectDirectoryPath, identity, objcAnalyzer);
        } catch (OomKillDetected oom) {
            if (!objcAnalyzer) {
                // Already running the lighter profile — nothing left to fall back to.
                throw new RuntimeException("Ghidra decompilation failed: " + oom.getMessage(), oom);
            }
            log.warn("Ghidra was OOM-killed with the Objective-C analyzer enabled ({}). "
                    + "Retrying once with the Objective-C analyzer disabled — classes/functions ingested "
                    + "from this retry will be less complete for ObjC-heavy code, but Swift/C decompilation "
                    + "and string extraction are unaffected.", oom.getMessage());
            try {
                runOnce(executableFilePath, projectDirectoryPath, identity, false);
                log.warn("Retry without the Objective-C analyzer succeeded. Consider raising this host's "
                        + "memory limit (e.g. systemd MemoryMax=) or GHIDRA_MAX_MEM so future scans of "
                        + "similarly large binaries don't need this fallback.");
            } catch (Exception retryFailure) {
                throw new RuntimeException(
                        "Ghidra decompilation failed on first attempt (OOM-killed, objcAnalyzer=true): "
                                + oom.getMessage()
                                + " | retry without Objective-C analyzer also failed: " + retryFailure.getMessage(),
                        retryFailure);
            }
        } catch (Exception e) {
            throw new RuntimeException("Ghidra decompilation failed: " + describeFailure(e), e);
        }
    }

    /** Thrown internally when a Ghidra subprocess exit is diagnosed as an OOM-kill, to drive the one-shot retry. */
    private static final class OomKillDetected extends RuntimeException {
        OomKillDetected(String message) { super(message); }
    }

    private void runOnce(String executableFilePath, String projectDirectoryPath, BinaryIdentity identity,
                          boolean objcAnalyzer) throws IOException, InterruptedException {
        log.info("Starting Ghidra decompilation: {} (objcAnalyzer={})", executableFilePath, objcAnalyzer);

        ServerSocket serverSocket = openServerSocket();
        List<String> activeLibs = identity.libraryPrefixes();
        String libsArg = String.join(",", activeLibs);

        try (ServerSocket ss = serverSocket) {
            Process ghidra = launchGhidra(
                    executableFilePath, projectDirectoryPath, ss.getLocalPort(), libsArg, objcAnalyzer);
            streamGhidraOutput(ghidra);

            ss.setSoTimeout(ACCEPT_POLL_MS);

            log.info("Waiting for Ghidra script connection on port {}", ss.getLocalPort());

            try (Socket hb = acceptWithWatchdog(ss, ghidra, "heartbeat");
                 BufferedReader hbIn = new BufferedReader(new InputStreamReader(hb.getInputStream()))) {
                String beat = hbIn.readLine();
                if (!"HEARTBEAT".equals(beat))
                    throw new RuntimeException("Expected HEARTBEAT, got: " + beat);
                log.info("Heartbeat received");
            }

            Socket dataSocket = acceptWithWatchdog(ss, ghidra, "data");
            dataSocket.setSoTimeout(0);

            try (BufferedReader in = new BufferedReader(new InputStreamReader(dataSocket.getInputStream()))) {
                String confirm = in.readLine();
                if (!"CONNECTED".equals(confirm))
                    throw new RuntimeException("Expected CONNECTED, got: " + confirm);
                log.info("Ghidra script connected — reading analysis data (decompile may take a while)");

                processData(in, identity);
            }

            ghidra.waitFor();
            log.info("Ghidra decompilation complete");

        } catch (OomOnAccept oom) {
            log.error("Ghidra subprocess was OOM-killed: {}", oom.getMessage());
            throw new OomKillDetected(oom.getMessage());
        } catch (Exception e) {
            log.error("Ghidra decompilation failed", e);
            throw e;
        }
    }

    private String describeFailure(Exception e) {
        String detail = e.getMessage();
        String scriptHint = summarizeCapturedErrors();
        if (scriptHint != null && !scriptHint.isBlank())
            detail = detail + " | ghidra-script: " + scriptHint;
        return detail;
    }

    // ── connection watchdog ──────────────────────────────────────────────────

    /** Poll interval for {@link ServerSocket#accept()} — short for responsive aliveness check. */
    private static final int ACCEPT_POLL_MS = 2_000;

    /**
     * Total time we'll wait for Ghidra's post-script to <em>dial</em> back (accept phase only).
     * Once CONNECTED is received, reading payload blocks is unbounded ({@code soTimeout=0});
     * DumpClassData sends CONNECTED before heavy decompile so this deadline is not spent waiting
     * for full analysis to finish.
     */
    static final long ACCEPT_DEADLINE_MS = 30L * 60 * 1000;   // 30 minutes

    /**
     * Like {@link ServerSocket#accept()} but checks the Ghidra subprocess on every
     * timeout tick. Throws if Ghidra exits before the script connects (e.g. Mach-O
     * loader NPE during import) or if the overall accept deadline elapses.
     *
     * <p>This is the bug-fix for the "CLI hangs forever when Ghidra crashes during
     * import" failure mode: the post-script never connects, so {@code accept()} with
     * no timeout would block indefinitely.
     *
     * <p>Deadline scope: establishing the TCP connection only. After DumpClassData sends
     * CONNECTED, {@link #processData} may block for a long time while the script decompiles;
     * that phase is intentionally not bounded by {@link #ACCEPT_DEADLINE_MS}.
     */
    private static Socket acceptWithWatchdog(ServerSocket ss, Process ghidra, String phase)
            throws IOException, InterruptedException {
        long deadline = System.currentTimeMillis() + ACCEPT_DEADLINE_MS;
        while (true) {
            try {
                return ss.accept();
            } catch (SocketTimeoutException e) {
                if (!ghidra.isAlive()) {
                    int rc;
                    try { rc = ghidra.exitValue(); }
                    catch (IllegalThreadStateException x) { rc = -1; }
                    String hint = diagnoseExit(rc);
                    String message = "Ghidra subprocess exited with rc=" + rc + " before " + phase +
                            " connection — " + hint;
                    if (rc == SIGNAL_EXIT_BASE + SIGKILL) {
                        // Let the caller decide whether to retry with a lighter analyzer profile
                        // instead of surfacing this as a generic Mach-O parse failure.
                        throw new OomOnAccept(message);
                    }
                    throw new IOException(message);
                }
                if (System.currentTimeMillis() > deadline) {
                    log.error("Timed out after {} min waiting for Ghidra {} connection",
                            ACCEPT_DEADLINE_MS / 60000, phase);
                    ghidra.destroyForcibly();
                    throw new IOException(
                            "Timed out (" + ACCEPT_DEADLINE_MS / 60000 + " min) waiting for Ghidra "
                            + phase + " connection — subprocess killed");
                }
                // else: still alive, still within deadline → keep polling
            }
        }
    }

    /**
     * Raised when the Ghidra subprocess exited with rc=137 (SIGKILL) during the accept phase —
     * almost always an OOM-kill (confirmed via cgroup {@code memory.events} when available).
     * Kept as an {@link IOException} subtype so existing catch sites still work unless they
     * specifically want to branch on "was this an OOM" (see {@link #decompile}).
     */
    static final class OomOnAccept extends IOException {
        OomOnAccept(String message) { super(message); }
    }

    /** Exit code a shell reports when a process is killed by signal N (POSIX: 128+N). */
    private static final int SIGNAL_EXIT_BASE = 128;
    private static final int SIGKILL = 9;

    /**
     * Build a diagnostic hint for a Ghidra subprocess exit code, distinguishing:
     * <ul>
     *   <li>rc=0 — post-script never dialed back despite the process exiting cleanly
     *       (classpath/script bug, not an import failure)</li>
     *   <li>rc=137 (128+SIGKILL) with corroborating cgroup {@code memory.events} —
     *       OOM-killed by the kernel/cgroup, <em>not</em> a Mach-O parse failure</li>
     *   <li>rc=137 without cgroup evidence (e.g. macOS, or cgroups v1) — still flagged
     *       as "likely killed (OOM or external signal)" rather than asserting parse failure</li>
     *   <li>anything else — the original Mach-O parse/import failure hypothesis</li>
     * </ul>
     */
    static String diagnoseExit(int rc) {
        if (rc == 0) {
            return "post-script likely failed before connecting (missing org.json, bad script args, "
                    + "or socket error). If the log shows Import succeeded, this is NOT a Mach-O "
                    + "parse failure — check DumpClassData / [ghidra-output] for script errors.";
        }
        if (rc == SIGNAL_EXIT_BASE + SIGKILL) {
            CgroupOomStatus oom = readCgroupOomStatus();
            if (oom.observed()) {
                return "process was SIGKILLed and this cgroup's memory.events shows " + oom.oomKillCount()
                        + " OOM kill(s) (memory.max=" + oom.memoryMaxDescription() + ") — "
                        + "this is an out-of-memory kill, NOT a Mach-O parse/import failure. "
                        + "The binary/analyzer combination needs more memory (raise the service's "
                        + "MemoryMax, e.g. systemd MemoryMax=) or a lighter analyzer profile "
                        + "(e.g. disable the Objective-C analyzer for very large binaries).";
            }
            return "process was SIGKILLed (rc=137). No cgroup memory.events evidence was available on this "
                    + "host to confirm OOM, but SIGKILL is far more consistent with an OOM-kill (by the "
                    + "kernel or a memory-limited cgroup/container) than a Mach-O parse failure — check "
                    + "`dmesg`/`journalctl -k` for \"Out of memory\" / \"Killed process\" around this time "
                    + "before assuming the binary itself is malformed.";
        }
        return "most likely Mach-O parse/import failure; check the [ghidra-output] ERROR lines.";
    }

    /** Minimal snapshot of what we could learn from this process's cgroup v2 memory controller. */
    record CgroupOomStatus(boolean observed, long oomKillCount, String memoryMaxDescription) {
        static CgroupOomStatus unavailable() { return new CgroupOomStatus(false, 0, "unknown"); }
    }

    /**
     * Best-effort read of {@code /sys/fs/cgroup/.../memory.events} and {@code memory.max} for
     * <em>this</em> process's own cgroup (Ghidra runs as a child, so it shares it). Cgroups v1,
     * non-Linux hosts, or missing read permission all degrade gracefully to "unavailable" —
     * this is a diagnostic aid, never a hard requirement for reporting the failure.
     */
    static CgroupOomStatus readCgroupOomStatus() {
        try {
            String selfCgroup = Files.readString(Path.of("/proc/self/cgroup")).strip();
            // cgroup v2 single-hierarchy line looks like "0::/user.slice/.../malimite-web.service"
            String relative = selfCgroup.substring(selfCgroup.indexOf("/"));
            Path base = Path.of("/sys/fs/cgroup" + relative);

            Path eventsFile = base.resolve("memory.events");
            if (!Files.isReadable(eventsFile)) return CgroupOomStatus.unavailable();

            long oomKill = 0;
            for (String line : Files.readAllLines(eventsFile)) {
                String[] parts = line.trim().split("\\s+");
                if (parts.length == 2 && "oom_kill".equals(parts[0])) {
                    oomKill = Long.parseLong(parts[1]);
                }
            }

            String maxDesc = "unknown";
            Path maxFile = base.resolve("memory.max");
            if (Files.isReadable(maxFile)) {
                String raw = Files.readString(maxFile).strip();
                maxDesc = "max".equals(raw) ? "unlimited" : (Long.parseLong(raw) / (1024 * 1024)) + "MiB";
            }

            return new CgroupOomStatus(oomKill > 0, oomKill, maxDesc);
        } catch (Exception e) {
            return CgroupOomStatus.unavailable();
        }
    }

    // ── Ghidra process ────────────────────────────────────────────────────────

    private Process launchGhidra(String execPath, String projDir, int port, String libsArg,
                                 boolean enableObjectiveC) throws IOException {
        List<String> cmd = new ArrayList<>();
        cmd.add(config.analyzeHeadlessPath().toString());
        cmd.add(projDir);
        cmd.add(ghidraProjectName);
        cmd.add("-import");
        cmd.add(execPath);
        cmd.add("-scriptPath");
        cmd.add(scriptDir.toString());
        cmd.add("-postScript");
        cmd.add("DumpClassData.java");
        cmd.add(String.valueOf(port));
        cmd.add(libsArg);
        if (enableObjectiveC) {
            cmd.add("-enableAnalyzer");
            cmd.add("Objective-C");
        }
        cmd.add("-enableAnalyzer");
        cmd.add("String Extraction");
        cmd.add("-disableAnalyzer");
        cmd.add("Decompiler Parameter ID");
        cmd.add("-disableAnalyzer");
        cmd.add("DWARF");
        // Invokes the native decompiler per function during auto-analysis (before our own
        // DumpClassData skip-list ever runs) purely to reconstruct switch statements for
        // readability — large ObjC/Swift binaries can balloon container memory here.
        // Measured against UnCrackable-Level1/Level2 (llm disabled, rule-based scan only):
        // vulnerability_counts identical with this analyzer on vs off in both apps.
        cmd.add("-disableAnalyzer");
        cmd.add("Decompiler Switch Analysis");
        cmd.add("-skipAnalysisPrompt");
        cmd.add("-deleteProject");

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        // Ghidra 11.x script loader (Felix OSGi) needs a supported JDK (17/21).
        // Homebrew Java 23/25 often yields: osgi.ee=UNKNOWN → DumpClassData ClassNotFoundException.
        Path ghidraJava = resolveGhidraJavaHome();
        if (ghidraJava != null) {
            pb.environment().put("JAVA_HOME", ghidraJava.toString());
            // analyzeHeadless prefers JAVA_HOME; clear conflicting launcher vars
            pb.environment().remove("JDK_HOME");
            log.info("Using JAVA_HOME={} for Ghidra (set GHIDRA_JAVA_HOME to override)", ghidraJava);
        } else if (isSupportedGhidraJava(Runtime.version().feature())) {
            // resolveGhidraJavaHome only knows macOS/Homebrew locations; on Linux the default JDK is what Ghidra uses
            log.info("Using the default JDK ({}) for Ghidra (set GHIDRA_JAVA_HOME to override)", Runtime.version().feature());
        } else {
            log.warn("No Java 17/21 found for Ghidra and the default JDK is {} — using it anyway. "
                    + "If DumpClassData fails with osgi.ee=UNKNOWN, install Temurin 21 and set GHIDRA_JAVA_HOME.",
                    Runtime.version().feature());
        }

        // analyzeHeadless's own launch.sh hardcodes MAXMEM=2G and builds "-Xmx${MAXMEM}" into
        // VMARGS_FROM_LAUNCH_SH, placed *before* any pass-thru caller args on the final java
        // command line. We cannot append to that command line without patching the vendored
        // Ghidra script, but JAVA_TOOL_OPTIONS is read by the JVM at startup and -Xmx given
        // there wins over an earlier -Xmx on the actual command line — see
        // https://docs.oracle.com/en/java/javase/21/docs/specs/man/java.html (JAVA_TOOL_OPTIONS).
        // This raises Ghidra's heap ceiling (default 4096 MB here vs Ghidra's stock 2048 MB)
        // for large Swift/ObjC binaries without modifying vendor files. The JVM prints one
        // "Picked up JAVA_TOOL_OPTIONS" line to stderr (redirected into our [ghidra-output] log).
        int maxMemMb = config.ghidraMaxMemMb();
        String existingToolOpts = pb.environment().get("JAVA_TOOL_OPTIONS");
        String xmxOpt = "-Xmx" + maxMemMb + "m";
        pb.environment().put("JAVA_TOOL_OPTIONS",
                existingToolOpts == null || existingToolOpts.isBlank()
                        ? xmxOpt
                        : existingToolOpts + " " + xmxOpt);
        log.info("Ghidra heap ceiling: {} MB (override with GHIDRA_MAX_MEM env var)", maxMemMb);

        log.info("Launching: {}", String.join(" ", pb.command()));
        return pb.start();
    }

    /** JDKs Ghidra's OSGi script loader recognises (the running JVM is used as a proxy for the one analyzeHeadless finds). */
    static boolean isSupportedGhidraJava(int feature) {
        return feature == 17 || feature == 21;
    }

    /**
     * Prefer an explicit {@code GHIDRA_JAVA_HOME}, else the newest installed JDK 21/17.
     * Returns null when nothing suitable is found (caller keeps the ambient JVM).
     */
    static Path resolveGhidraJavaHome() {
        String explicit = System.getenv("GHIDRA_JAVA_HOME");
        if (explicit != null && !explicit.isBlank()) {
            Path p = Path.of(explicit);
            if (Files.isDirectory(p)) return p;
            log.warn("GHIDRA_JAVA_HOME={} is not a directory — ignoring", explicit);
        }
        // macOS java_home helper
        for (String ver : List.of("21", "17")) {
            Path home = runJavaHome(ver);
            if (home != null) return home;
        }
        // Common Homebrew locations
        for (String candidate : List.of(
                "/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home",
                "/opt/homebrew/opt/openjdk@21",
                "/usr/local/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home",
                "/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home",
                "/opt/homebrew/opt/openjdk@17")) {
            Path p = Path.of(candidate);
            if (Files.isRegularFile(p.resolve("bin/java"))) return p;
        }
        return null;
    }

    private static Path runJavaHome(String version) {
        try {
            Process p = new ProcessBuilder("/usr/libexec/java_home", "-v", version)
                    .redirectErrorStream(true)
                    .start();
            String out;
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                out = r.readLine();
            }
            if (!p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS)) {
                p.destroyForcibly();
                return null;
            }
            if (p.exitValue() != 0 || out == null || out.isBlank()) return null;
            Path home = Path.of(out.trim());
            return Files.isRegularFile(home.resolve("bin/java")) ? home : null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Recurring Ghidra analyzer exceptions that are noisy but non-fatal (the binary still
     * decompiles) — known issues in Ghidra's own analyzers, not something Malimite can fix.
     * Each pattern's first occurrence (and its full stack trace) is still logged verbatim;
     * every later line matching the same pattern is counted and suppressed instead, with a
     * one-line summary emitted when the Ghidra subprocess exits. This is what made this
     * exact failure's analysis.log balloon to 74 KB of "Unsupported Objective C type
     * encoding: ]" stack traces for scan 039733fe-9923-47e1-89cc-28127f57f0cf.
     */
    private static final String[] KNOWN_NOISY_GHIDRA_ERRORS = {
            "Unsupported Objective C type encoding",
    };

    private final Map<String, Integer> noisyErrorCounts = new java.util.concurrent.ConcurrentHashMap<>();

    private void streamGhidraOutput(Process process) {
        Thread t = new Thread(() -> {
            // Tracks whether the line(s) we're currently reading are stack-trace continuation
            // lines ("\tat ...") belonging to an *already-summarized* (2nd+) noisy exception —
            // only those get suppressed; the first full exception+trace is always logged.
            String[] suppressingPattern = {null};
            try (BufferedReader r = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = r.readLine()) != null) {
                    if (suppressingPattern[0] != null) {
                        if (isStackTraceContinuation(line)) {
                            continue; // part of the exception we're already counting — drop it
                        }
                        suppressingPattern[0] = null; // trace ended; fall through to normal handling
                    }

                    String noisyPattern = matchNoisyHeader(line);
                    if (noisyPattern != null) {
                        int seen = noisyErrorCounts.merge(noisyPattern, 1, Integer::sum);
                        if (seen == 1) {
                            log.info("Ghidra: {}", line); // first occurrence: log header + full trace below
                        } else {
                            if (seen == 2) {
                                log.info("Ghidra: (further \"{}\" occurrences will be counted, not logged "
                                        + "line-by-line — known non-fatal Ghidra ObjC analyzer limitation)",
                                        noisyPattern);
                            }
                            suppressingPattern[0] = noisyPattern;
                            continue; // drop this header line and its upcoming trace
                        }
                    } else {
                        log.info("Ghidra: {}", line);
                    }

                    if (line.contains("SCRIPT ERROR") || line.contains("osgi.ee")
                            || line.contains("ClassNotFoundException: DumpClassData")
                            || line.contains("GhidraScriptLoadException")) {
                        ghidraErrors.addLast(line);
                        while (ghidraErrors.size() > 8) ghidraErrors.pollFirst();
                    }
                }
                logNoisyErrorSummary();
            } catch (IOException e) {
                log.warn("Error reading Ghidra stdout", e);
                logNoisyErrorSummary();
            }
        }, "ghidra-output");
        t.setDaemon(true);
        t.start();
    }

    private static boolean isStackTraceContinuation(String line) {
        return line.startsWith("\tat ") || line.isBlank() || line.equals(" ");
    }

    private static String matchNoisyHeader(String line) {
        for (String pattern : KNOWN_NOISY_GHIDRA_ERRORS) {
            if (line.contains(pattern)) return pattern;
        }
        return null;
    }

    private void logNoisyErrorSummary() {
        noisyErrorCounts.forEach((pattern, count) ->
                log.info("Ghidra: suppressed {} total occurrence(s) of known non-fatal error \"{}\" "
                        + "(full trace shown once above)", count, pattern));
    }

    private String summarizeCapturedErrors() {
        if (ghidraErrors.isEmpty()) return null;
        String joined = String.join(" :: ", ghidraErrors);
        if (joined.contains("osgi.ee") || joined.contains("UNKNOWN")) {
            return "DumpClassData failed to load (osgi.ee=UNKNOWN) — Ghidra was likely started with "
                    + "Java 23+/25. Use Java 21: export GHIDRA_JAVA_HOME=$(/usr/libexec/java_home -v 21)";
        }
        if (joined.contains("DumpClassData") || joined.contains("SCRIPT ERROR")) {
            return joined.length() > 400 ? joined.substring(0, 400) + "…" : joined;
        }
        return joined.length() > 400 ? joined.substring(0, 400) + "…" : joined;
    }

    // ── data ingestion ────────────────────────────────────────────────────────

    private void processData(BufferedReader in, BinaryIdentity identity) throws IOException {
        JSONArray classData    = readBlock(in, "END_CLASS_DATA");
        JSONArray machoData    = readBlockAsArray(in, "END_MACHO_DATA");  // stored for future use
        JSONArray functionData = readBlock(in, "END_DATA");
        JSONArray stringData   = readBlock(in, "END_STRING_DATA");

        log.info("Received {} classes, {} functions, {} strings",
                classData.length(), functionData.length(), stringData.length());

        ingestFunctions(functionData, identity);
        ingestStrings(stringData, identity.executableName());
    }

    // Known entry-point function names (ObjC, Swift AppDelegate, C main)
    private static final java.util.Set<String> ENTRY_POINT_NAMES = java.util.Set.of(
            "main",
            "applicationDidFinishLaunching:",
            "application:didFinishLaunchingWithOptions:",
            "applicationDidBecomeActive:",
            "applicationWillTerminate:",
            "+initialize",
            "+load"
    );

    private void ingestFunctions(JSONArray functionData, BinaryIdentity identity) {
        Map<String, JSONArray>   classToFunctions = new HashMap<>();
        List<SqliteStore.DecompilationResult> decomps   = new ArrayList<>();
        List<SyntaxParser.FunctionRefResult>  fnRefs    = new ArrayList<>();
        List<SyntaxParser.VariableRefResult>  varRefs   = new ArrayList<>();
        List<SyntaxParser.TypeInfoResult>     typeInfos = new ArrayList<>();
        List<String[]>                        entryPts  = new ArrayList<>(); // [fn, cls]

        String execName = identity.executableName();
        List<String> activeLibs = identity.libraryPrefixes();
        // Android native libs also treat JNI_OnLoad as an entry point
        boolean androidNative = identity.classNamespacePrefix() != null
                && identity.classNamespacePrefix().startsWith("native:");

        for (int i = 0; i < functionData.length(); i++) {
            JSONObject obj          = functionData.getJSONObject(i);
            String     functionName = obj.getString("FunctionName");
            String     className    = obj.getString("ClassName");
            String     decomp       = obj.getString("DecompiledCode");

            if (identity.isSwift() && functionName.startsWith("_$s")) {
                DemangleSwift.DemangledName dn = DemangleSwift.demangleSwiftName(functionName);
                if (dn != null) {
                    className    = dn.className();
                    functionName = dn.fullMethodName();
                    log.debug("Demangled: {}", functionName);
                }
            }

            if (className == null || className.isBlank()) className = "Global";

            if (identity.classNamespacePrefix() != null) {
                className = identity.classNamespacePrefix() + "/" + className;
            }

            final String cls = className;
            final String fn  = functionName;

            boolean isLib = activeLibs.stream().anyMatch(lib ->
                    cls.equals(lib) || cls.startsWith(lib) || cls.contains("/" + lib));

            if (isLib) {
                String libFn = cls + "::" + fn;
                decomps.add(new SqliteStore.DecompilationResult(
                        libFn, "Libraries", "", execName, "GHIDRA"));
                classToFunctions.computeIfAbsent("Libraries", k -> new JSONArray()).put(libFn);
            } else {
                decomp = decomp.replaceAll("/\\*.*?\\*/", ""); // remove Ghidra inline comments
                if (!decomp.isBlank() && !decomp.startsWith("// Class:")) {
                    decomp = "// Class: " + cls + "\n// Function: " + fn + "\n\n" + decomp.trim();
                }

                decomps.add(new SqliteStore.DecompilationResult(
                        fn, cls, decomp, execName, "GHIDRA"));
                classToFunctions.computeIfAbsent(cls, k -> new JSONArray()).put(fn);

                if (ENTRY_POINT_NAMES.contains(fn) || fn.equals("entry")
                        || (androidNative && ("JNI_OnLoad".equals(fn) || fn.startsWith("Java_"))))
                    entryPts.add(new String[]{fn, cls});

                if (!decomp.isBlank()) {
                    SyntaxParser sp = new SyntaxParser(execName);
                    sp.setContext(fn, cls);
                    sp.collectCrossReferences(decomp);
                    fnRefs.addAll(sp.getFunctionRefResults());
                    varRefs.addAll(sp.getVariableRefResults());
                    typeInfos.addAll(sp.getTypeInfoResults());
                }
            }
        }

        store.insertFunctionDecompilations(decomps);
        store.insertFunctionReferences(fnRefs);
        store.insertLocalVariableReferences(varRefs);
        store.insertTypeInformations(typeInfos);
        for (String[] ep : entryPts)
            store.insertEntryPoint(ep[0], ep[1], execName);

        for (Map.Entry<String, JSONArray> e : classToFunctions.entrySet())
            store.insertClass(e.getKey(), e.getValue().toString(), execName);

        log.info("Ingested {} functions across {} class(es), {} entry points",
                decomps.size(), classToFunctions.size(), entryPts.size());
    }

    private void ingestStrings(JSONArray strings, String executableName) {
        for (int i = 0; i < strings.length(); i++) {
            JSONObject s = strings.getJSONObject(i);
            store.insertMachoString(
                    s.getString("address"),
                    s.getString("value"),
                    s.getString("segment"),
                    s.optString("label", ""),
                    executableName);
        }
        log.info("Ingested {} strings", strings.length());
    }

    // ── socket helpers ────────────────────────────────────────────────────────

    private static ServerSocket openServerSocket() {
        // Bind IPv4 loopback explicitly — DumpClassData connects to 127.0.0.1
        // (InetAddress.getLoopbackAddress() can be ::1 on dual-stack hosts).
        try {
            InetAddress loopback = InetAddress.getByName("127.0.0.1");
            for (int port = BASE_PORT; port < BASE_PORT + MAX_PORT_TRIES; port++) {
                try {
                    ServerSocket ss = new ServerSocket(port, 50, loopback);
                    log.info("Listening on 127.0.0.1:{}", port);
                    return ss;
                } catch (IOException ignored) {}
            }
        } catch (IOException e) {
            throw new RuntimeException("Cannot resolve 127.0.0.1 for Ghidra IPC", e);
        }
        throw new RuntimeException("No available port in range " + BASE_PORT + "–" + (BASE_PORT + MAX_PORT_TRIES));
    }

    private static JSONArray readBlock(BufferedReader in, String terminator) throws IOException {
        StringBuilder sb = new StringBuilder();
        String line;
        while (!(line = in.readLine()).equals(terminator)) sb.append(line).append('\n');
        return new JSONArray(sb.toString().trim());
    }

    /** Reads a block that the script sends as a JSON object (machoData), discards it for now. */
    private static JSONArray readBlockAsArray(BufferedReader in, String terminator) throws IOException {
        StringBuilder sb = new StringBuilder();
        String line;
        while (!(line = in.readLine()).equals(terminator)) sb.append(line).append('\n');
        // machoData is a JSONObject (segment map) — not yet consumed; return empty array
        return new JSONArray();
    }

    // ── resource extraction ───────────────────────────────────────────────────

    private static Path extractScriptToTemp() throws IOException {
        Path dir = Files.createTempDirectory("malimite-ghidra-");
        Path dst = dir.resolve("DumpClassData.java");
        try (InputStream in = GhidraRunner.class.getResourceAsStream("/ghidra/DumpClassData.java")) {
            if (in == null)
                throw new IllegalStateException("DumpClassData.java not found in classpath resources");
            Files.copy(in, dst, StandardCopyOption.REPLACE_EXISTING);
        }
        bundleOrgJsonForScript(dir);
        log.info("Ghidra script extracted to {}", dst);
        return dir;
    }

    /**
     * DumpClassData.java imports {@code org.json.*}. Ghidra's script classpath does not
     * include Malimite's shaded deps, so we place a thin {@code json.jar} next to the script.
     *
     * <p>Prefer the embedded {@code /ghidra/json.jar} resource (pristine {@code org.json}
     * package). The CLI fat jar relocates {@code org.json} → {@code io.malimite.shaded.org.json}
     * to avoid NoClassDefFoundError / classpath clashes, so extracting {@code org/json/} from
     * the running fat jar is only a last-resort fallback (and may find nothing after relocate).
     */
    static void bundleOrgJsonForScript(Path scriptDir) throws IOException {
        Path out = scriptDir.resolve("json.jar");
        try (InputStream bundled = GhidraRunner.class.getResourceAsStream("/ghidra/json.jar")) {
            if (bundled != null) {
                Files.copy(bundled, out, StandardCopyOption.REPLACE_EXISTING);
                log.info("Bundled embedded json.jar for Ghidra script");
                return;
            }
        }
        try {
            var src = org.json.JSONObject.class.getProtectionDomain().getCodeSource();
            if (src == null || src.getLocation() == null) {
                log.warn("Cannot locate org.json on classpath — DumpClassData may fail in Ghidra");
                return;
            }
            Path loc = Path.of(src.getLocation().toURI());
            if (Files.isRegularFile(loc) && loc.getFileName().toString().startsWith("json")) {
                Files.copy(loc, out, StandardCopyOption.REPLACE_EXISTING);
                log.info("Bundled {} for Ghidra script classpath", loc.getFileName());
                return;
            }
            if (Files.isRegularFile(loc)) {
                // Fat-jar fallback: may be relocated (io/malimite/shaded/org/json/) — try both.
                extractPackageToJar(loc, "org/json/", out);
                if (Files.size(out) > 0) {
                    log.info("Extracted org.json package from {} into {}", loc.getFileName(), out.getFileName());
                    return;
                }
                Path relocatedOut = scriptDir.resolve("json-relocated-tmp.jar");
                extractPackageToJar(loc, "io/malimite/shaded/org/json/", relocatedOut);
                if (Files.size(relocatedOut) > 0) {
                    // Cannot rewrite package names here; embedded json.jar is required for Ghidra.
                    Files.deleteIfExists(relocatedOut);
                    log.warn("Classpath only has relocated org.json — embed /ghidra/json.jar for DumpClassData");
                    return;
                }
                Files.deleteIfExists(relocatedOut);
            }
        } catch (Exception e) {
            log.warn("Failed to bundle org.json for Ghidra script: {}", e.getMessage());
            return;
        }
        log.warn("org.json was not bundled — DumpClassData may fail to compile inside Ghidra");
    }

    /** Copy a single package prefix from {@code sourceJar} into a new jar at {@code destJar}. */
    static void extractPackageToJar(Path sourceJar, String packagePrefix, Path destJar) throws IOException {
        try (JarFile jf = new JarFile(sourceJar.toFile());
             JarOutputStream jos = new JarOutputStream(Files.newOutputStream(destJar))) {
            Enumeration<JarEntry> entries = jf.entries();
            while (entries.hasMoreElements()) {
                JarEntry e = entries.nextElement();
                String name = e.getName();
                if (e.isDirectory() || !name.startsWith(packagePrefix)) continue;
                jos.putNextEntry(new JarEntry(name));
                try (InputStream in = jf.getInputStream(e)) {
                    in.transferTo(jos);
                }
                jos.closeEntry();
            }
        }
    }
}
