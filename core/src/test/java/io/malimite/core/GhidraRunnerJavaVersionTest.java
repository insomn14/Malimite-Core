package io.malimite.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GhidraRunnerJavaVersionTest {
    @Test
    void onlyJdk17And21AreTreatedAsSupportedForGhidraScripts() {
        assertTrue(GhidraRunner.isSupportedGhidraJava(17));
        assertTrue(GhidraRunner.isSupportedGhidraJava(21));
        for (int v : new int[] {8, 11, 22, 23, 25}) assertFalse(GhidraRunner.isSupportedGhidraJava(v), "java " + v);
    }
}
