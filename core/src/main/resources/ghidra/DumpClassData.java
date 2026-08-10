import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.address.Address;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.program.model.listing.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StringDataType;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.json.JSONObject;
import org.json.JSONArray;

public class DumpClassData extends GhidraScript {

    /** Per-function decompile budget (seconds). 0 would use Ghidra's default and can stall for ages. */
    private static final int DECOMPILE_TIMEOUT_SECS = 45;

    /** Log progress every N non-library decompiles so Malimite/Ghidra logs show the script is alive. */
    private static final int DECOMPILE_PROGRESS_EVERY = 50;

    private int port = -1;
    private List<String> libraryPrefixes = Collections.emptyList();

    private void parseArgs() {
        String[] args = getScriptArgs();
        if (args == null || args.length < 1) {
            printerr("Insufficient arguments. Expected: <port> [libraries]");
            this.port = -1;
            return;
        }
        try {
            this.port = Integer.parseInt(args[0].trim());
        } catch (NumberFormatException e) {
            printerr("Invalid port argument: " + args[0]);
            this.port = -1;
            return;
        }
        if (args.length >= 2 && args[1] != null && !args[1].isBlank()) {
            this.libraryPrefixes = Arrays.asList(args[1].split(","));
        } else {
            this.libraryPrefixes = Collections.emptyList();
        }
        println("DumpClassData args: port=" + this.port + " libraries=" + this.libraryPrefixes.size());
    }

    private boolean isLibraryNamespace(String namespace) {
        return libraryPrefixes.stream()
            .anyMatch(prefix -> namespace.startsWith(prefix));
    }

    private int getPort() {
        return this.port;
    }

    private String formatNamespaceName(String namespaceName) {
        if ("<global>".equals(namespaceName)) {
            return "Global";
        } else if ("<EXTERNAL>".equals(namespaceName)) {
            return "External";
        }
        return namespaceName;
    }

    private JSONArray extractClassFunctionData(Program program) {
        FunctionManager functionManager = program.getFunctionManager();
        List<JSONObject> classFunctionData = new ArrayList<>();

        Map<String, List<String>> namespaceFunctionData = new HashMap<>();

        for (Function function : functionManager.getFunctions(true)) {
            Namespace namespace = function.getParentNamespace();
            String namespaceName = formatNamespaceName(namespace != null ? namespace.getName() : "<global>");

            namespaceFunctionData.computeIfAbsent(namespaceName, k -> new ArrayList<>()).add(function.getName());
        }

        for (Map.Entry<String, List<String>> entry : namespaceFunctionData.entrySet()) {
            JSONObject classObject = new JSONObject();
            classObject.put("ClassName", entry.getKey());
            classObject.put("Functions", new JSONArray(entry.getValue()));
            classFunctionData.add(classObject);
        }

        return new JSONArray(classFunctionData);
    }

    private JSONObject listDefinedDataInAllSegments(Program program) {
        Memory memory = program.getMemory();
        Listing listing = program.getListing();
        Map<String, JSONObject> dataStructure = new HashMap<>();

        for (MemoryBlock block : memory.getBlocks()) {
            Address start = block.getStart();
            Address end = block.getEnd();
            String name = block.getName();

            JSONObject segmentData = new JSONObject();
            segmentData.put("start", start.toString());
            segmentData.put("end", end.toString());
            JSONArray dataArray = new JSONArray();

            DataIterator dataIterator = listing.getDefinedData(start, true);
            while (dataIterator.hasNext()) {
                Data data = dataIterator.next();
                if (!block.contains(data.getAddress())) {
                    continue;
                }

                String label = data.getLabel();
                String value = data.getDefaultValueRepresentation();
                String address = data.getAddress().toString();

                JSONObject dataEntry = new JSONObject();
                dataEntry.put("label", label != null ? label : "Unnamed");
                dataEntry.put("value", value);
                dataEntry.put("address", address);
                dataArray.put(dataEntry);
            }

            segmentData.put("data", dataArray);
            dataStructure.put(name, segmentData);
        }

        return new JSONObject(dataStructure);
    }

    private JSONArray listFunctionsAndNamespaces(Program program) {
        DecompInterface decompInterface = new DecompInterface();
        FunctionManager functionManager = program.getFunctionManager();
        Map<String, List<Function>> namespaceFunctionsMap = new HashMap<>();
        JSONArray jsonOutput = new JSONArray();

        try {
            decompInterface.openProgram(program);

            // Collect functions for each namespace
            for (Function function : functionManager.getFunctions(true)) {
                Namespace namespace = function.getParentNamespace();
                String namespaceName = formatNamespaceName(namespace != null ? namespace.getName() : "<global>");

                // Skip decompilation if namespace is a library
                if (isLibraryNamespace(namespaceName)) {
                    JSONObject jsonEntry = new JSONObject();
                    jsonEntry.put("FunctionName", function.getName());
                    jsonEntry.put("ClassName", namespaceName);
                    jsonEntry.put("DecompiledCode", "");
                    jsonOutput.put(jsonEntry);
                    continue;
                }

                namespaceFunctionsMap.computeIfAbsent(namespaceName, k -> new ArrayList<>()).add(function);
            }

            int totalToDecompile = namespaceFunctionsMap.values().stream().mapToInt(List::size).sum();
            println("Decompiling " + totalToDecompile + " non-library function(s) "
                    + "(timeout=" + DECOMPILE_TIMEOUT_SECS + "s each)");

            int completed = 0;
            int failed = 0;

            for (Map.Entry<String, List<Function>> entry : namespaceFunctionsMap.entrySet()) {
                String namespace = entry.getKey();
                List<Function> functions = entry.getValue();

                for (Function function : functions) {
                    String decompiledCode = "";
                    try {
                        var decompiledFunction = decompInterface.decompileFunction(
                                function, DECOMPILE_TIMEOUT_SECS, new ConsoleTaskMonitor());
                        if (decompiledFunction != null && decompiledFunction.decompileCompleted()) {
                            decompiledCode = decompiledFunction.getDecompiledFunction().getC();
                        } else {
                            failed++;
                            decompiledCode = "";
                        }
                    } catch (Exception e) {
                        // Never hang the whole script on a single bad function
                        failed++;
                        printerr("Decompile failed for " + namespace + "::" + function.getName()
                                + ": " + e.getMessage());
                        decompiledCode = "";
                    }

                    JSONObject jsonEntry = new JSONObject();
                    jsonEntry.put("FunctionName", function.getName());
                    jsonEntry.put("ClassName", namespace);
                    jsonEntry.put("DecompiledCode", decompiledCode);
                    jsonOutput.put(jsonEntry);

                    completed++;
                    if (completed % DECOMPILE_PROGRESS_EVERY == 0 || completed == totalToDecompile) {
                        println("Decompile progress: " + completed + "/" + totalToDecompile
                                + " (failed/timed-out: " + failed + ")");
                    }
                }
            }

            println("Decompilation finished: " + completed + " function(s), "
                    + failed + " failed/timed-out");
        } finally {
            decompInterface.dispose();
        }
        return jsonOutput;
    }

    private JSONArray extractStrings(Program program) {
        Memory memory = program.getMemory();
        Listing listing = program.getListing();
        JSONArray stringsArray = new JSONArray();

        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized()) continue;

            DataIterator dataIterator = listing.getDefinedData(block.getStart(), true);
            while (dataIterator.hasNext()) {
                Data data = dataIterator.next();
                if (!block.contains(data.getAddress())) continue;

                DataType dataType = data.getDataType();
                if (dataType instanceof StringDataType) {
                    String value = data.getDefaultValueRepresentation();
                    if (value.length() >= 5) {
                        JSONObject stringObj = new JSONObject();
                        stringObj.put("address", data.getAddress().toString());
                        stringObj.put("value", value);
                        stringObj.put("segment", block.getName());
                        stringObj.put("label", data.getLabel() != null ? data.getLabel() : "");
                        stringsArray.put(stringObj);
                    }
                }
            }
        }
        return stringsArray;
    }

    /**
     * Protocol with Malimite {@code GhidraRunner.decompile}:
     * <ol>
     *   <li>HEARTBEAT on a short-lived connection (handled in {@link #run()})</li>
     *   <li>Second connection: send CONNECTED immediately, then stream blocks as work finishes:
     *       class → END_CLASS_DATA, macho → END_MACHO_DATA, functions → END_DATA,
     *       strings → END_STRING_DATA</li>
     * </ol>
     * CONNECTED must precede heavy decompile work so the Java-side accept watchdog returns quickly.
     */
    private void openDataSocketAndStream(int port) throws IOException {
        try (Socket socket = new Socket("127.0.0.1", port);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {

            // Early CONNECTED — before any long decompile work
            out.println("CONNECTED");
            println("Data connection established (CONNECTED) — beginning analysis...");

            println("Extracting class/function index...");
            JSONArray classData = extractClassFunctionData(currentProgram);
            out.println(classData.toString(4));
            out.println("END_CLASS_DATA");
            println("Sent class data (" + classData.length() + " namespaces)");

            println("Extracting defined data in segments...");
            JSONObject machoData = listDefinedDataInAllSegments(currentProgram);
            out.println(machoData.toString(4));
            out.println("END_MACHO_DATA");
            println("Sent macho/segment data");

            println("Decompiling functions (this may take a while on large Swift apps)...");
            JSONArray functionData = listFunctionsAndNamespaces(currentProgram);
            out.println(functionData.toString(4));
            out.println("END_DATA");
            println("Sent function data (" + functionData.length() + " entries)");

            println("Extracting strings...");
            JSONArray stringData = extractStrings(currentProgram);
            out.println(stringData.toString(4));
            out.println("END_STRING_DATA");
            println("Sent string data (" + stringData.length() + " strings) — script complete");
        }
    }

    @Override
    public void run() throws Exception {
        println("Running DumpClassData script");
        parseArgs();

        if (port <= 0) {
            printerr("DumpClassData: refusing to run with invalid port=" + port);
            return;
        }

        // Heartbeat first — use 127.0.0.1 so we don't hit IPv6 localhost (::1) mismatches
        try (Socket heartbeatSocket = new Socket("127.0.0.1", port);
             PrintWriter heartbeatOut = new PrintWriter(heartbeatSocket.getOutputStream(), true)) {
            heartbeatOut.println("HEARTBEAT");
            println("Heartbeat sent successfully to 127.0.0.1:" + port);
        } catch (IOException e) {
            printerr("Failed to establish heartbeat to 127.0.0.1:" + port + " — " + e.getMessage());
            throw e; // surface as script failure instead of silent success
        }

        // Open data socket + CONNECTED immediately, then stream payload blocks as work completes.
        // Do NOT decompile before CONNECTED — that races the Java accept watchdog (30 min).
        try {
            openDataSocketAndStream(port);
        } catch (IOException e) {
            printerr("Error on data socket to 127.0.0.1:" + port + " — " + e.getMessage());
            throw e;
        }
    }
}
