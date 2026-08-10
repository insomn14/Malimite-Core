package io.malimite.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Optional smoke test — runs only when JADX_HOME is set and points at a real install.
 * Does not run in default CI without JADX.
 */
class JadxRunnerSmokeTest {

    @TempDir Path tmp;

    @Test
    @EnabledIfEnvironmentVariable(named = "JADX_HOME", matches = ".+")
    void resolveBinaryFromJadxHome() throws Exception {
        Path bin = JadxRunner.resolveJadx(Path.of(System.getenv("JADX_HOME")));
        assertTrue(Files.exists(bin), "jadx binary should exist: " + bin);
    }
}
