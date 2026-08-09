package io.mailmite.core;

import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Structural / contract tests for the DumpClassData ↔ GhidraRunner IPC protocol.
 * Ensures CONNECTED is sent before heavy decompile work (the Captain-Nohook timeout bug).
 */
class GhidraRunnerProtocolTest {

    private static String loadDumpClassDataSource() throws Exception {
        try (InputStream in = GhidraRunner.class.getResourceAsStream("/ghidra/DumpClassData.java")) {
            assertNotNull(in, "DumpClassData.java must be on the classpath as a resource");
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @Test void acceptDeadlineIsBoundedAndDocumentedAsAcceptOnly() {
        // 30 minutes — connection establishment only; post-CONNECTED reads are unbounded
        assertEquals(30L * 60 * 1000, GhidraRunner.ACCEPT_DEADLINE_MS);
        assertTrue(GhidraRunner.ACCEPT_DEADLINE_MS > 0);
    }

    @Test void dumpClassDataSendsConnectedBeforeDecompileWork() throws Exception {
        String src = loadDumpClassDataSource();

        // Protocol: HEARTBEAT in run(), then openDataSocketAndStream sends CONNECTED first
        assertTrue(src.contains("HEARTBEAT"), "script must send HEARTBEAT");
        assertTrue(src.contains("openDataSocketAndStream"),
                "script should open the data socket via openDataSocketAndStream");

        int methodStart = src.indexOf("private void openDataSocketAndStream");
        assertTrue(methodStart >= 0, "openDataSocketAndStream method missing");
        String methodBody = src.substring(methodStart);
        // Truncate at next top-level method/run for a rough body window
        int next = methodBody.indexOf("public void run()");
        if (next > 0) methodBody = methodBody.substring(0, next);

        int connected = methodBody.indexOf("CONNECTED");
        int classExtract = methodBody.indexOf("extractClassFunctionData");
        int decompile = methodBody.indexOf("listFunctionsAndNamespaces");

        assertTrue(connected >= 0, "CONNECTED must be sent on the data socket");
        assertTrue(classExtract > connected,
                "class extraction must happen after CONNECTED, not before");
        assertTrue(decompile > connected,
                "function decompile must happen after CONNECTED (early-connect fix)");
    }

    @Test void dumpClassDataUsesFinitePerFunctionDecompileTimeout() throws Exception {
        String src = loadDumpClassDataSource();
        Matcher m = Pattern.compile("DECOMPILE_TIMEOUT_SECS\\s*=\\s*(\\d+)").matcher(src);
        assertTrue(m.find(), "DECOMPILE_TIMEOUT_SECS constant required");
        int timeout = Integer.parseInt(m.group(1));
        assertTrue(timeout >= 30 && timeout <= 120,
                "per-function timeout should be finite (30–120s), was " + timeout);

        // Must not call decompileFunction with 0 (Ghidra default / unbounded)
        assertFalse(src.matches("(?s).*decompileFunction\\s*\\(\\s*function\\s*,\\s*0\\s*,.*"),
                "decompileFunction must not use timeout=0");
        assertTrue(src.contains("decompileFunction(\n") || src.contains("decompileFunction("),
                "must still call decompileFunction");
        assertTrue(src.contains("DECOMPILE_TIMEOUT_SECS"),
                "decompile call should use DECOMPILE_TIMEOUT_SECS");
    }

    @Test void dumpClassDataLogsDecompileProgress() throws Exception {
        String src = loadDumpClassDataSource();
        assertTrue(src.contains("DECOMPILE_PROGRESS_EVERY"),
                "progress interval constant required");
        assertTrue(src.contains("Decompile progress:"),
                "should log periodic decompile progress");
    }
}
