package io.mailmite.core;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.reflect.Method;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Regression tests for the "CLI hangs forever when Ghidra crashes during import"
 * bug. Verifies the watchdog inside {@link GhidraRunner#acceptWithWatchdog} aborts
 * promptly when the subprocess dies before the post-script can connect.
 *
 * <p>Note: {@link GhidraRunner#ACCEPT_DEADLINE_MS} bounds only the accept/dial phase
 * (heartbeat then data CONNECTED). DumpClassData sends CONNECTED before heavy decompile
 * so long Swift analysis is not killed by this deadline — see {@link GhidraRunnerProtocolTest}.
 */
class GhidraRunnerWatchdogTest {

    /** Invoke the private static method via reflection — keeps the helper package-private. */
    private static Socket acceptWithWatchdog(ServerSocket ss, Process p, String phase) throws Exception {
        Method m = GhidraRunner.class.getDeclaredMethod(
                "acceptWithWatchdog", ServerSocket.class, Process.class, String.class);
        m.setAccessible(true);
        try {
            return (Socket) m.invoke(null, ss, p, phase);
        } catch (java.lang.reflect.InvocationTargetException e) {
            // Unwrap so JUnit's assertThrows sees the real exception
            if (e.getCause() instanceof RuntimeException re) throw re;
            if (e.getCause() instanceof IOException ioe) throw ioe;
            throw new RuntimeException(e.getCause());
        }
    }

    @Test void throwsPromptlyWhenSubprocessExitsBeforeConnect() throws Exception {
        try (ServerSocket ss = new ServerSocket(0)) {
            ss.setSoTimeout(500);  // override the default poll interval

            // Spawn a subprocess that exits immediately (simulates Ghidra crashing during import)
            Process p = new ProcessBuilder("true").start();
            p.waitFor();   // make sure it has exited before we enter the watchdog
            assertFalse(p.isAlive(), "test setup: subprocess should be dead");

            Instant t0 = Instant.now();
            IOException ex = assertThrows(IOException.class,
                    () -> acceptWithWatchdog(ss, p, "test-phase"));

            Duration elapsed = Duration.between(t0, Instant.now());
            assertTrue(elapsed.compareTo(Duration.ofSeconds(3)) < 0,
                    "watchdog should fire within a few seconds; took " + elapsed);

            String msg = ex.getMessage();
            assertTrue(msg.contains("Ghidra subprocess exited"),
                    "error message should mention subprocess exit: " + msg);
            assertTrue(msg.contains("test-phase"),
                    "error message should mention which phase failed: " + msg);
            // rc=0 from `true` → post-script hint, not Mach-O parse claim
            assertTrue(msg.contains("post-script") || msg.contains("Mach-O"),
                    "error message should include a cause hint: " + msg);
        }
    }

    @Test void returnsSocketWhenClientConnectsBeforeSubprocessDies() throws Exception {
        try (ServerSocket ss = new ServerSocket(0)) {
            ss.setSoTimeout(500);

            // Long-lived subprocess so the watchdog has no reason to abort
            Process p = new ProcessBuilder("sleep", "30").start();

            // Connect from a separate thread shortly after the watchdog starts polling
            int port = ss.getLocalPort();
            Thread client = new Thread(() -> {
                try (Socket s = new Socket("127.0.0.1", port)) {
                    s.getOutputStream().write("HELLO\n".getBytes());
                    s.getOutputStream().flush();
                } catch (IOException ignored) {}
            });
            client.start();

            try (Socket accepted = acceptWithWatchdog(ss, p, "happy")) {
                assertNotNull(accepted, "watchdog should return the accepted socket");
                assertTrue(accepted.isConnected());
            } finally {
                p.destroyForcibly();
                client.join(2000);
            }
        }
    }
}
