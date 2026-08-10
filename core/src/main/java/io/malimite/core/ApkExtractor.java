package io.malimite.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Extracts an APK ZIP into a work directory and locates key artifacts. */
public final class ApkExtractor {

    private static final Logger log = LoggerFactory.getLogger(ApkExtractor.class);

    private ApkExtractor() {}

    public record ExtractionResult(
            Path rootDir,
            Path manifestPath,
            List<Path> dexFiles,
            List<Path> nativeLibs,
            Path resDir,
            Path assetsDir
    ) {}

    /** Preferred Android ABI for native Ghidra analysis. */
    public static final String PREFERRED_ABI = "arm64-v8a";

    /**
     * Returns native libs under {@code lib/arm64-v8a/} only (primary Ghidra target).
     * Empty when the APK has no arm64-v8a libraries.
     */
    public static List<Path> preferArm64NativeLibs(List<Path> nativeLibs) {
        if (nativeLibs == null || nativeLibs.isEmpty()) return List.of();
        String marker = "/lib/" + PREFERRED_ABI + "/";
        return nativeLibs.stream()
                .filter(p -> p.toString().replace('\\', '/').contains(marker))
                .sorted()
                .toList();
    }

    /** Distinct ABI folder names found under {@code lib/<abi>/}. */
    public static List<String> detectAbis(List<Path> nativeLibs) {
        if (nativeLibs == null || nativeLibs.isEmpty()) return List.of();
        return nativeLibs.stream()
                .map(p -> p.toString().replace('\\', '/'))
                .map(s -> {
                    int lib = s.indexOf("/lib/");
                    if (lib < 0) return null;
                    String rest = s.substring(lib + 5);
                    int slash = rest.indexOf('/');
                    return slash > 0 ? rest.substring(0, slash) : null;
                })
                .filter(a -> a != null && !a.isBlank())
                .distinct()
                .sorted()
                .toList();
    }

    public static ExtractionResult extract(Path apkPath, Path workDir) throws IOException {
        log.info("Extracting APK: {} → {}", apkPath, workDir);
        Files.createDirectories(workDir);
        unzip(apkPath, workDir);

        Path manifest = workDir.resolve("AndroidManifest.xml");
        if (!Files.exists(manifest))
            throw new IOException("AndroidManifest.xml missing after extract");

        List<Path> dexFiles = new ArrayList<>();
        List<Path> nativeLibs = new ArrayList<>();
        try (var walk = Files.walk(workDir)) {
            walk.filter(Files::isRegularFile).forEach(p -> {
                String name = p.getFileName().toString().toLowerCase(Locale.ROOT);
                if (name.matches("classes\\d*\\.dex")) dexFiles.add(p);
                else if (name.endsWith(".so") && p.toString().contains("/lib/")) nativeLibs.add(p);
            });
        }
        if (dexFiles.isEmpty())
            throw new IOException("No classes*.dex found after extract");

        Path resDir = workDir.resolve("res");
        Path assetsDir = workDir.resolve("assets");
        log.info("APK extract: dex={} nativeLibs={}", dexFiles.size(), nativeLibs.size());
        return new ExtractionResult(
                workDir,
                manifest,
                List.copyOf(dexFiles),
                List.copyOf(nativeLibs),
                Files.isDirectory(resDir) ? resDir : null,
                Files.isDirectory(assetsDir) ? assetsDir : null);
    }

    private static void unzip(Path zip, Path dest) throws IOException {
        try (ZipFile zf = new ZipFile(zip.toFile())) {
            Enumeration<? extends ZipEntry> entries = zf.entries();
            while (entries.hasMoreElements()) {
                ZipEntry e = entries.nextElement();
                Path out = dest.resolve(e.getName()).normalize();
                if (!out.startsWith(dest))
                    throw new IOException("Zip slip blocked: " + e.getName());
                if (e.isDirectory()) {
                    Files.createDirectories(out);
                    continue;
                }
                Files.createDirectories(out.getParent());
                try (InputStream in = zf.getInputStream(e);
                     OutputStream os = Files.newOutputStream(out)) {
                    in.transferTo(os);
                }
            }
        }
    }
}
