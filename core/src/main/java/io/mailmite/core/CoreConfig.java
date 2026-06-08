package io.mailmite.core;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

/**
 * Headless configuration sourced from environment variables and system properties.
 * No file persistence, no GUI — replaces Malimite's Config.java for server-side use.
 *
 * Env vars:
 *   GHIDRA_HOME   — required (path to Ghidra installation)
 *   EXTRA_LIBS    — optional comma-separated library prefixes to add
 *   REMOVE_LIBS   — optional comma-separated library prefixes to remove
 */
public class CoreConfig {

    private final Path ghidraHome;
    private final List<String> addedLibraries;
    private final List<String> removedLibraries;
    private final String osType;

    public CoreConfig(Path ghidraHome) {
        this.ghidraHome      = ghidraHome;
        this.osType          = System.getProperty("os.name", "").toLowerCase();
        this.addedLibraries  = parseList(System.getenv("EXTRA_LIBS"));
        this.removedLibraries = parseList(System.getenv("REMOVE_LIBS"));
    }

    /** Resolves GHIDRA_HOME from the supplied path or falls back to the GHIDRA_HOME env var. */
    public static CoreConfig fromEnv(Path explicitGhidraHome) {
        Path home = explicitGhidraHome != null
                ? explicitGhidraHome
                : resolveGhidraFromEnv();
        return new CoreConfig(home);
    }

    private static Path resolveGhidraFromEnv() {
        String env = System.getenv("GHIDRA_HOME");
        if (env == null || env.isBlank())
            throw new IllegalStateException("GHIDRA_HOME env var is not set and no explicit path provided");
        return Paths.get(env);
    }

    public Path getGhidraHome() {
        return ghidraHome;
    }

    public Path analyzeHeadlessPath() {
        String script = isWindows() ? "analyzeHeadless.bat" : "analyzeHeadless";
        return ghidraHome.resolve("support").resolve(script);
    }

    public boolean isWindows() {
        return osType.contains("win");
    }

    public boolean isMac() {
        return osType.contains("mac");
    }

    public boolean isUnix() {
        return osType.contains("nix") || osType.contains("nux") || osType.contains("aix");
    }

    public List<String> getAddedLibraries() {
        return addedLibraries;
    }

    public List<String> getRemovedLibraries() {
        return removedLibraries;
    }

    private static List<String> parseList(String csv) {
        if (csv == null || csv.isBlank()) return List.of();
        return Arrays.asList(csv.split(","));
    }
}
