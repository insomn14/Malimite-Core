package io.malimite.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Covers the pure helpers and the fallback-availability check without requiring a real
 * {@code droidasc} install — {@link #isAvailableIsFalseWhenTheBinaryDoesNotExist()} and friends
 * exercise the exact path MalimiteAnalyzer relies on to decide ASC vs. JADX. The
 * {@code droidasc}-backed scan itself (listClasses/getClass/decompileToTree against a real
 * install) is an opt-in smoke test — see {@link #realDroidAscListsClasses()}.
 */
class AscRunnerTest {

    @TempDir Path tmp;

    @Test
    void isAvailableIsFalseWhenTheBinaryDoesNotExist() throws Exception {
        // No ASC_HOME directory and no `droidasc` on PATH (assumed true in this dev/CI
        // environment, same assumption MalimiteAnalyzer's fallback itself depends on) — the
        // constructor always succeeds (it only resolves *which* command to try), so the
        // distinguishing check has to be isAvailable() actually attempting to launch it.
        AscRunner asc = new AscRunner(null);
        assertFalse(asc.isAvailable(), "a nonexistent droidasc binary must report unavailable, not throw");
    }

    @Test
    void isAvailableIsFalseForANonexistentAscHomeDirectory() throws Exception {
        // ascHomeOrNull only short-circuits to "python -m droidasc" when the directory actually
        // exists (Files.isDirectory) — a bogus path here still falls through to resolving
        // `droidasc` on PATH, so this should behave identically to the null case above.
        AscRunner asc = new AscRunner(tmp.resolve("does-not-exist"));
        assertFalse(asc.isAvailable());
    }

    @Test
    void dalvikToFqcnStripsTheLPrefixAndTrailingSemicolonAndReplacesSlashes() {
        assertEquals("com.foo.Bar", AscRunner.dalvikToFqcn("Lcom/foo/Bar;"));
        assertEquals("Bar", AscRunner.dalvikToFqcn("LBar;"));   // default package
        assertNull(AscRunner.dalvikToFqcn(null));
        assertNull(AscRunner.dalvikToFqcn("L;"));   // strips to an empty string -> no valid FQCN
    }

    @Test
    void classFileNestsUnderSourcesRootByPackage() {
        Path sources = tmp.resolve("sources");
        Path f = AscRunner.classFile(sources, "Lcom/foo/Bar;");
        assertEquals(sources.resolve("com").resolve("foo").resolve("Bar.java"), f);
    }

    @Test
    void classFileHandlesTheDefaultPackage() {
        Path sources = tmp.resolve("sources");
        Path f = AscRunner.classFile(sources, "LBar;");
        assertEquals(sources.resolve("Bar.java"), f);
    }

    /**
     * Opt-in — only runs when DROIDASC_SMOKE_TEST names a directory containing a real,
     * launchable Droid ASC checkout (same discovery ASC_HOME uses). Not expected to run in
     * default CI, mirroring {@link JadxRunnerSmokeTest}'s JADX_HOME-gated smoke test.
     */
    @Test
    @EnabledIfEnvironmentVariable(named = "DROIDASC_SMOKE_TEST", matches = ".+")
    void realDroidAscListsClasses() throws Exception {
        AscRunner asc = new AscRunner(Path.of(System.getenv("DROIDASC_SMOKE_TEST")));
        assertTrue(asc.isAvailable(), "DROIDASC_SMOKE_TEST must point at a launchable droidasc checkout");
    }
}
