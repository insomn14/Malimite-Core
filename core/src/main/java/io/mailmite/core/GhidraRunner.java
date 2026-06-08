package io.mailmite.core;

import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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

    public GhidraRunner(String executableBaseName, CoreConfig config, SqliteStore store) throws IOException {
        this.ghidraProjectName = executableBaseName + "_mailmite";
        this.config            = config;
        this.store             = store;
        this.scriptDir         = extractScriptToTemp();
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

            // Handshake: HEARTBEAT → close → new connection → CONNECTED
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
                log.info("Ghidra script connected — reading analysis data");

                processData(in, macho, activeLibs);
            }

            ghidra.waitFor();
            log.info("Ghidra decompilation complete");

        } catch (Exception e) {
            log.error("Ghidra decompilation failed", e);
            throw new RuntimeException("Ghidra decompilation failed: " + e.getMessage(), e);
        }
    }

    // ── connection watchdog ──────────────────────────────────────────────────

    /** Poll interval for {@link ServerSocket#accept()} — short for responsive aliveness check. */
    private static final int ACCEPT_POLL_MS = 2_000;

    /** Total time we'll wait for Ghidra's post-script to dial back. Generous, but bounded. */
    private static final long ACCEPT_DEADLINE_MS = 30L * 60 * 1000;   // 30 minutes

    /**
     * Like {@link ServerSocket#accept()} but checks the Ghidra subprocess on every
     * timeout tick. Throws if Ghidra exits before the script connects (e.g. Mach-O
     * loader NPE during import) or if the overall deadline elapses.
     *
     * <p>This is the bug-fix for the "CLI hangs forever when Ghidra crashes during
     * import" failure mode: the post-script never connects, so {@code accept()} with
     * no timeout would block indefinitely.
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
                    throw new IOException(
                            "Ghidra subprocess exited with rc=" + rc + " before " + phase +
                            " connection — most likely Mach-O parse failure; check the " +
                            "[ghidra-output] lines in analysis.log");
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
        log.info("Launching: {}", String.join(" ", pb.command()));
        return pb.start();
    }

    private void streamGhidraOutput(Process process) {
        Thread t = new Thread(() -> {
            try (BufferedReader r = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = r.readLine()) != null) log.info("Ghidra: {}", line);
            } catch (IOException e) {
                log.warn("Error reading Ghidra stdout", e);
            }
        }, "ghidra-output");
        t.setDaemon(true);
        t.start();
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
        for (int port = BASE_PORT; port < BASE_PORT + MAX_PORT_TRIES; port++) {
            try {
                ServerSocket ss = new ServerSocket(port);
                log.info("Listening on port {}", port);
                return ss;
            } catch (IOException ignored) {}
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
        log.info("Ghidra script extracted to {}", dst);
        return dir;
    }
}
