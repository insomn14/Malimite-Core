package io.mailmite.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Invokes the JADX CLI to decompile an APK into Java sources.
 * Resolve binary via {@code JADX_HOME}, {@code JADX_PATH}, or PATH.
 */
public final class JadxRunner {

    private static final Logger log = LoggerFactory.getLogger(JadxRunner.class);

    /** Default wall-clock timeout for JADX (large apps can be slow). */
    private static final long DEFAULT_TIMEOUT_MINUTES = 45;

    private final Path jadxBinary;

    public JadxRunner(Path jadxHomeOrNull) throws IOException {
        this.jadxBinary = resolveJadx(jadxHomeOrNull);
        log.info("Using JADX binary: {}", jadxBinary);
    }

    /**
     * Decompile {@code apkPath} into {@code outputDir}. Returns the sources root
     * (usually {@code outputDir/sources} or {@code outputDir} itself).
     */
    public Path decompile(Path apkPath, Path outputDir) throws Exception {
        Files.createDirectories(outputDir);
        List<String> cmd = new ArrayList<>();
        cmd.add(jadxBinary.toString());
        cmd.add("--deobf");
        cmd.add("--show-bad-code");
        cmd.add("-d");
        cmd.add(outputDir.toString());
        cmd.add(apkPath.toString());

        log.info("Running JADX: {}", String.join(" ", cmd));
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process proc = pb.start();

        StringBuilder out = new StringBuilder();
        try (BufferedReader r = new BufferedReader(
                new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                out.append(line).append('\n');
                if (line.toLowerCase().contains("error") || line.contains("%"))
                    log.debug("jadx: {}", line);
            }
        }

        boolean finished = proc.waitFor(DEFAULT_TIMEOUT_MINUTES, TimeUnit.MINUTES);
        if (!finished) {
            proc.destroyForcibly();
            throw new IOException("JADX timed out after " + DEFAULT_TIMEOUT_MINUTES + " minutes");
        }
        int code = proc.exitValue();
        // JADX may return non-zero when some classes fail; accept if sources exist
        Path sources = outputDir.resolve("sources");
        Path root = Files.isDirectory(sources) ? sources : outputDir;
        boolean hasJava;
        try (var walk = Files.walk(root)) {
            hasJava = walk.anyMatch(p -> p.toString().endsWith(".java"));
        }
        if (!hasJava) {
            throw new IOException("JADX failed (exit=" + code + "): no .java output\n"
                    + out.substring(0, Math.min(out.length(), 2000)));
        }
        if (code != 0)
            log.warn("JADX exited {} but produced sources under {}", code, root);
        else
            log.info("JADX finished → {}", root);
        return root;
    }

    static Path resolveJadx(Path jadxHomeOrNull) throws IOException {
        if (jadxHomeOrNull != null) {
            Path candidate = findBinaryUnder(jadxHomeOrNull);
            if (candidate != null) return candidate;
        }
        String home = System.getenv("JADX_HOME");
        if (home != null && !home.isBlank()) {
            Path candidate = findBinaryUnder(Path.of(home));
            if (candidate != null) return candidate;
        }
        String pathEnv = System.getenv("JADX_PATH");
        if (pathEnv != null && !pathEnv.isBlank()) {
            Path p = Path.of(pathEnv);
            if (Files.isExecutable(p)) return p;
        }
        Path fromPath = which("jadx");
        if (fromPath != null) return fromPath;
        throw new IOException(
                "JADX not found. Set JADX_HOME (install root) or JADX_PATH (binary), or put jadx on PATH.");
    }

    private static Path findBinaryUnder(Path home) {
        if (home == null) return null;
        Path[] candidates = {
                home.resolve("bin/jadx"),
                home.resolve("bin/jadx.bat"),
                home.resolve("jadx"),
                home
        };
        for (Path c : candidates) {
            if (Files.isRegularFile(c) && (Files.isExecutable(c) || c.toString().endsWith(".bat")))
                return c;
        }
        return null;
    }

    private static Path which(String name) {
        String path = System.getenv("PATH");
        if (path == null) return null;
        for (String dir : path.split(java.io.File.pathSeparator)) {
            Path p = Path.of(dir, name);
            if (Files.isExecutable(p)) return p;
            Path bat = Path.of(dir, name + ".bat");
            if (Files.isRegularFile(bat)) return bat;
        }
        return null;
    }
}
