package io.mailmite.core;

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
 * Runs Ghidra headless analysis on a Mach-O binary and ingests results into SqliteStore.
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
        this.ghidraProjectName = sanitizeProjectName(executableBaseName) + "_mailmite";
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

    public void decompile(String executableFilePath, String projectDirectoryPath, Macho macho) {
        log.info("Starting Ghidra decompilation: {}", executableFilePath);

        ServerSocket serverSocket = openServerSocket();
        List<String> activeLibs  = LibraryDefinitions.getActiveLibraries(config);
        String libsArg           = String.join(",", activeLibs);

        try (ServerSocket ss = serverSocket) {
            Process ghidra = launchGhidra(executableFilePath, projectDirectoryPath, ss.getLocalPort(), libsArg);
            streamGhidraOutput(ghidra);

            // Short poll interval so we notice a dead Ghidra subprocess quickly,
            // total deadline generous enough for slow imports of large binaries.
            ss.setSoTimeout(ACCEPT_POLL_MS);

            log.info("Waiting for Ghidra script connection on port {}", ss.getLocalPort());

            // Handshake (DumpClassData):
            //   1) HEARTBEAT on a short-lived connection
            //   2) New connection with CONNECTED immediately (before heavy decompile)
            //   3) Stream END_* blocks while decompile proceeds; processData blocks on reads
            // ACCEPT_DEADLINE_MS applies only to establishing each accept(), not to post-CONNECTED
            // payload transfer (dataSocket soTimeout=0 allows long Swift decompiles).
            try (Socket hb = acceptWithWatchdog(ss, ghidra, "heartbeat");
                 BufferedReader hbIn = new BufferedReader(new InputStreamReader(hb.getInputStream()))) {
                String beat = hbIn.readLine();
                if (!"HEARTBEAT".equals(beat))
                    throw new RuntimeException("Expected HEARTBEAT, got: " + beat);
                log.info("Heartbeat received");
            }

            Socket dataSocket = acceptWithWatchdog(ss, ghidra, "data");
            // Unlimited read timeout: script may decompile for a long time after CONNECTED
            // before sending END_CLASS_DATA / END_DATA / etc.
            dataSocket.setSoTimeout(0);

            try (BufferedReader in = new BufferedReader(new InputStreamReader(dataSocket.getInputStream()))) {
                String confirm = in.readLine();
                if (!"CONNECTED".equals(confirm))
                    throw new RuntimeException("Expected CONNECTED, got: " + confirm);
                log.info("Ghidra script connected — reading analysis data (decompile may take a while)");

                processData(in, macho, activeLibs);
            }

            ghidra.waitFor();
            log.info("Ghidra decompilation complete");

        } catch (Exception e) {
            String detail = e.getMessage();
            String scriptHint = summarizeCapturedErrors();
            if (scriptHint != null && !scriptHint.isBlank())
                detail = detail + " | ghidra-script: " + scriptHint;
            log.error("Ghidra decompilation failed", e);
            throw new RuntimeException("Ghidra decompilation failed: " + detail, e);
        }
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
                    String hint = (rc == 0)
                            ? "post-script likely failed before connecting (missing org.json, bad script args, "
                              + "or socket error). If the log shows Import succeeded, this is NOT a Mach-O "
                              + "parse failure — check DumpClassData / [ghidra-output] for script errors."
                            : "most likely Mach-O parse/import failure; check the [ghidra-output] ERROR lines.";
                    throw new IOException(
                            "Ghidra subprocess exited with rc=" + rc + " before " + phase +
                            " connection — " + hint);
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

    // ── Ghidra process ────────────────────────────────────────────────────────

    private Process launchGhidra(String execPath, String projDir, int port, String libsArg)
            throws IOException {
        ProcessBuilder pb = new ProcessBuilder(
                config.analyzeHeadlessPath().toString(),
                projDir,
                ghidraProjectName,
                "-import",      execPath,
                "-scriptPath",  scriptDir.toString(),
                "-postScript",  "DumpClassData.java",
                String.valueOf(port),
                libsArg,
                "-enableAnalyzer",  "Objective-C",
                "-enableAnalyzer",  "String Extraction",
                "-disableAnalyzer", "Decompiler Parameter ID",
                "-disableAnalyzer", "DWARF",
                "-skipAnalysisPrompt",
                "-deleteProject"
        );
        pb.redirectErrorStream(true);
        // Ghidra 11.x script loader (Felix OSGi) needs a supported JDK (17/21).
        // Homebrew Java 23/25 often yields: osgi.ee=UNKNOWN → DumpClassData ClassNotFoundException.
        Path ghidraJava = resolveGhidraJavaHome();
        if (ghidraJava != null) {
            pb.environment().put("JAVA_HOME", ghidraJava.toString());
            // analyzeHeadless prefers JAVA_HOME; clear conflicting launcher vars
            pb.environment().remove("JDK_HOME");
            log.info("Using JAVA_HOME={} for Ghidra (set GHIDRA_JAVA_HOME to override)", ghidraJava);
        } else {
            log.warn("No Java 17/21 found for Ghidra — using process default. "
                    + "If DumpClassData fails with osgi.ee=UNKNOWN, install Temurin 21 and set GHIDRA_JAVA_HOME.");
        }
        log.info("Launching: {}", String.join(" ", pb.command()));
        return pb.start();
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

    private void streamGhidraOutput(Process process) {
        Thread t = new Thread(() -> {
            try (BufferedReader r = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = r.readLine()) != null) {
                    log.info("Ghidra: {}", line);
                    if (line.contains("SCRIPT ERROR") || line.contains("osgi.ee")
                            || line.contains("ClassNotFoundException: DumpClassData")
                            || line.contains("GhidraScriptLoadException")) {
                        ghidraErrors.addLast(line);
                        while (ghidraErrors.size() > 8) ghidraErrors.pollFirst();
                    }
                }
            } catch (IOException e) {
                log.warn("Error reading Ghidra stdout", e);
            }
        }, "ghidra-output");
        t.setDaemon(true);
        t.start();
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

    private void processData(BufferedReader in, Macho macho, List<String> activeLibs) throws IOException {
        JSONArray classData    = readBlock(in, "END_CLASS_DATA");
        JSONArray machoData    = readBlockAsArray(in, "END_MACHO_DATA");  // stored for future use
        JSONArray functionData = readBlock(in, "END_DATA");
        JSONArray stringData   = readBlock(in, "END_STRING_DATA");

        log.info("Received {} classes, {} functions, {} strings",
                classData.length(), functionData.length(), stringData.length());

        ingestFunctions(functionData, macho, activeLibs);
        ingestStrings(stringData, macho.getMachoExecutableName());
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

    private void ingestFunctions(JSONArray functionData, Macho macho, List<String> activeLibs) {
        Map<String, JSONArray>   classToFunctions = new HashMap<>();
        List<SqliteStore.DecompilationResult> decomps   = new ArrayList<>();
        List<SyntaxParser.FunctionRefResult>  fnRefs    = new ArrayList<>();
        List<SyntaxParser.VariableRefResult>  varRefs   = new ArrayList<>();
        List<SyntaxParser.TypeInfoResult>     typeInfos = new ArrayList<>();
        List<String[]>                        entryPts  = new ArrayList<>(); // [fn, cls]

        String execName = macho.getMachoExecutableName();

        for (int i = 0; i < functionData.length(); i++) {
            JSONObject obj          = functionData.getJSONObject(i);
            String     functionName = obj.getString("FunctionName");
            String     className    = obj.getString("ClassName");
            String     decomp       = obj.getString("DecompiledCode");

            // Swift name demangling (non-Mac headless always uses Java demangler)
            if (macho.isSwift() && functionName.startsWith("_$s")) {
                DemangleSwift.DemangledName dn = DemangleSwift.demangleSwiftName(functionName);
                if (dn != null) {
                    className    = dn.className();
                    functionName = dn.fullMethodName();
                    log.debug("Demangled: {}", functionName);
                }
            }

            if (className == null || className.isBlank()) className = "Global";

            final String cls = className;
            final String fn  = functionName;

            boolean isLib = activeLibs.stream().anyMatch(cls::startsWith);

            if (isLib) {
                String libFn = cls + "::" + fn;
                decomps.add(new SqliteStore.DecompilationResult(libFn, "Libraries", "", execName));
                classToFunctions.computeIfAbsent("Libraries", k -> new JSONArray()).put(libFn);
            } else {
                decomp = decomp.replaceAll("/\\*.*?\\*/", ""); // remove Ghidra inline comments
                if (!decomp.isBlank() && !decomp.startsWith("// Class:")) {
                    decomp = "// Class: " + cls + "\n// Function: " + fn + "\n\n" + decomp.trim();
                }

                decomps.add(new SqliteStore.DecompilationResult(fn, cls, decomp, execName));
                classToFunctions.computeIfAbsent(cls, k -> new JSONArray()).put(fn);

                if (ENTRY_POINT_NAMES.contains(fn) || fn.equals("entry"))
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
        Path dir = Files.createTempDirectory("mailmite-ghidra-");
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
     * include Mailmite's shaded deps, so we place a thin {@code json.jar} next to the script.
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
                extractPackageToJar(loc, "org/json/", out);
                if (Files.size(out) > 0) {
                    log.info("Extracted org.json package from {} into {}", loc.getFileName(), out.getFileName());
                    return;
                }
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
