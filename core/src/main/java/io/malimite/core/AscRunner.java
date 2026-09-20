package io.malimite.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Drives Droid ASC ({@code droidasc}) — an on-demand, zero-preprocessing Android
 * decompiler — as an alternative to JADX.
 *
 * <p>ASC treats the compiled APK as a read-only database and answers single
 * queries in milliseconds: {@code listclass} enumerates classes and
 * {@code getmanifest} decodes the binary manifest without inflating the whole
 * archive, while {@code getclass} extracts and decompiles exactly one class
 * (in-memory minimal DEX rebuild + Androguard/DAD).
 *
 * <p>To reuse the existing ingest pipeline unchanged, {@link #decompileToTree}
 * synthesises a JADX-shaped {@code sources/<pkg path>/<Class>.java} tree so
 * {@link JadxIngest} can consume it as-is.
 *
 * <p>Binary resolution: {@code --asc-home}/1st arg (a source checkout run via
 * {@code python -m droidasc}) &rarr; {@code ASC_HOME} env &rarr; a {@code droidasc}
 * console script on PATH. {@code ASC_PYTHON} overrides the interpreter.
 */
public final class AscRunner {

    private static final Logger log = LoggerFactory.getLogger(AscRunner.class);

    /** Wall-clock timeout per ASC invocation. */
    private static final long TIMEOUT_MINUTES = 30;

    private final List<String> command;
    private final Path workDir;

    public AscRunner(Path ascHomeOrNull) throws IOException {
        Path home = ascHomeOrNull;
        if (home == null) {
            String env = System.getenv("ASC_HOME");
            if (env != null && !env.isBlank()) home = Path.of(env);
        }
        String python = System.getenv().getOrDefault("ASC_PYTHON", "python3");
        if (home != null && Files.isDirectory(home)) {
            this.command = List.of(python, "-m", "droidasc");
            this.workDir = home;
            log.info("Using Droid ASC source at {} ({} -m droidasc)", home, python);
        } else {
            this.command = List.of("droidasc");
            this.workDir = null;
            log.info("Using Droid ASC from PATH (droidasc)");
        }
    }

    /** Decode AndroidManifest.xml straight from the APK (no full inflate). */
    public String manifest(Path apk) throws Exception {
        return run(List.of("getmanifest", apk.toString()));
    }

    /** List every class defined across all DEX entries, as Dalvik names. */
    public List<String> listClasses(Path apk) throws Exception {
        String out = run(List.of("listclass", apk.toString()));
        List<String> classes = new ArrayList<>();
        for (String line : out.split("\\R")) {
            String c = line.strip();
            if (c.length() > 2 && c.charAt(0) == 'L' && c.endsWith(";")) classes.add(c);
        }
        return classes;
    }

    /** Decompile a single class (Dalvik name, e.g. {@code Lcom/poc/Main;}). */
    public String getClass(Path apk, String dalvikName) throws Exception {
        return run(List.of("getclass", apk.toString(), dalvikName));
    }

    /**
     * Decompile in-scope classes into {@code outputRoot/sources/<pkg>/<Class>.java}
     * and return the sources root for {@link JadxIngest}.
     *
     * @param maxClasses 0 = no cap
     * @param threads    parallel {@code getclass} workers
     */
    public Path decompileToTree(Path apk, Path outputRoot, int maxClasses, int threads) throws Exception {
        List<String> all = listClasses(apk);
        List<String> wanted = new ArrayList<>();
        int skipped = 0;
        for (String dalvik : all) {
            String fqcn = dalvikToFqcn(dalvik);
            if (fqcn == null || AndroidLibraryDefinitions.shouldSkip(fqcn)) { skipped++; continue; }
            wanted.add(dalvik);
        }
        if (maxClasses > 0 && wanted.size() > maxClasses) {
            log.info("ASC: capping classes {} -> {} (max-asc-classes)", wanted.size(), maxClasses);
            wanted = new ArrayList<>(wanted.subList(0, maxClasses));
        }

        Path sources = outputRoot.resolve("sources");
        Files.createDirectories(sources);
        int workers = Math.max(1, threads);
        log.info("ASC: {} of {} class(es) in scope ({} skipped as library/noise), {} worker(s)",
                wanted.size(), all.size(), skipped, workers);

        AtomicInteger written = new AtomicInteger();
        AtomicInteger failed = new AtomicInteger();
        ExecutorService pool = Executors.newFixedThreadPool(workers);
        try {
            List<Future<?>> futures = new ArrayList<>();
            for (String dalvik : wanted) {
                futures.add(pool.submit(() -> {
                    try {
                        String java = getClass(apk, dalvik);
                        if (java == null || java.isBlank()) { failed.incrementAndGet(); return; }
                        Path target = classFile(sources, dalvik);
                        Files.createDirectories(target.getParent());
                        Files.writeString(target, java, StandardCharsets.UTF_8);
                        written.incrementAndGet();
                    } catch (Exception e) {
                        failed.incrementAndGet();
                        log.debug("ASC getclass failed for {}: {}", dalvik, e.getMessage());
                    }
                }));
            }
            for (Future<?> f : futures) {
                try {
                    f.get();
                } catch (Exception ignored) {
                    // per-class failures are already counted above
                }
            }
        } finally {
            pool.shutdown();
        }
        log.info("ASC: decompiled {} class(es), {} failed", written.get(), failed.get());
        return sources;
    }

    /** {@code Lcom/foo/Bar;} &rarr; {@code com.foo.Bar} */
    static String dalvikToFqcn(String dalvik) {
        if (dalvik == null) return null;
        String s = dalvik.strip();
        if (s.startsWith("L") && s.endsWith(";")) s = s.substring(1, s.length() - 1);
        s = s.replace('/', '.').strip();
        return s.isEmpty() ? null : s;
    }

    /** {@code sources/} + {@code Lcom/foo/Bar;} &rarr; {@code sources/com/foo/Bar.java} */
    static Path classFile(Path sourcesRoot, String dalvik) {
        String s = dalvik.strip();
        if (s.startsWith("L") && s.endsWith(";")) s = s.substring(1, s.length() - 1);
        int i = s.lastIndexOf('/');
        String pkg = i < 0 ? "" : s.substring(0, i);
        String simple = i < 0 ? s : s.substring(i + 1);
        Path dir = pkg.isEmpty() ? sourcesRoot : sourcesRoot.resolve(pkg);
        return dir.resolve(simple + ".java");
    }

    private String run(List<String> args) throws Exception {
        List<String> cmd = new ArrayList<>(command);
        cmd.addAll(args);
        ProcessBuilder pb = new ProcessBuilder(cmd);
        if (workDir != null) pb.directory(workDir.toFile());
        Process proc = pb.start();

        StringBuilder out = new StringBuilder();
        StringBuilder err = new StringBuilder();
        Thread tOut = new Thread(() -> drain(proc.getInputStream(), out));
        Thread tErr = new Thread(() -> drain(proc.getErrorStream(), err));
        tOut.start();
        tErr.start();

        boolean finished = proc.waitFor(TIMEOUT_MINUTES, TimeUnit.MINUTES);
        if (!finished) {
            proc.destroyForcibly();
            throw new IOException("ASC timed out after " + TIMEOUT_MINUTES + " min: "
                    + String.join(" ", args));
        }
        tOut.join(5000);
        tErr.join(5000);
        int code = proc.exitValue();
        if (code != 0) {
            String e = err.toString().strip();
            throw new IOException("ASC failed (exit=" + code + "): "
                    + (e.isEmpty() ? out.toString().strip() : e));
        }
        return out.toString();
    }

    private static void drain(InputStream in, StringBuilder sb) {
        try (BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) sb.append(line).append('\n');
        } catch (IOException ignored) {
            // stream closed on process exit
        }
    }
}
