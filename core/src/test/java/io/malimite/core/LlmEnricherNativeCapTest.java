package io.malimite.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** NATIVE-engine scans must not send every lifted function to the LLM (no network). */
class LlmEnricherNativeCapTest {

    private static int llmCalls(Path dir, String origin, int maxFunctions, int named, int unnamed) {
        AtomicInteger calls = new AtomicInteger();
        LlmProvider counting = (sys, user) -> { calls.incrementAndGet(); return "{\"vulnerabilities\":[]}"; };
        try (SqliteStore store = new SqliteStore(dir.resolve(origin + maxFunctions + ".sqlite").toString())) {
            List<SqliteStore.DecompilationResult> rows = new ArrayList<>();
            for (int i = 0; i < named; i++)
                rows.add(new SqliteStore.DecompilationResult("m" + i + ":", "Foo", "x = " + "y".repeat(i + 1) + ";", "App", origin));
            for (int i = 0; i < unnamed; i++)
                rows.add(new SqliteStore.DecompilationResult("sub_" + i, "Global", "z = 1;", "App", origin));
            store.insertFunctionDecompilations(rows);
            new LlmEnricher(counting, LlmMode.SUMMARIZE, LlmCache.NOOP, false)
                    .maxFunctions(maxFunctions).enrich(store, "App");
        }
        return calls.get();
    }

    @Test
    void nativeSkipsUnnamedSubFunctions(@TempDir Path dir) {
        assertEquals(5, llmCalls(dir, "NATIVE", 0, 5, 50));
    }

    @Test
    void nativeIsCappedByDefault(@TempDir Path dir) {
        assertEquals(LlmEnricher.NATIVE_DEFAULT_MAX_FUNCTIONS,
                llmCalls(dir, "NATIVE", 0, LlmEnricher.NATIVE_DEFAULT_MAX_FUNCTIONS + 40, 0));
    }

    @Test
    void explicitCapOverridesNativeDefault(@TempDir Path dir) {
        assertEquals(7, llmCalls(dir, "NATIVE", 7, 30, 0));
    }

    @Test
    void ghidraOriginIsUntouched(@TempDir Path dir) {
        assertEquals(55, llmCalls(dir, "GHIDRA", 0, 5, 50));
    }
}
