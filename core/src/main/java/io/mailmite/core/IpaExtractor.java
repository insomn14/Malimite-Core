package io.mailmite.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Extracts an IPA file and locates the primary Mach-O executable.
 * Port of Malimite's FileProcessing.java — Swing/Config/Project dependencies removed.
 */
public final class IpaExtractor {

    private static final Logger log = LoggerFactory.getLogger(IpaExtractor.class);

    private IpaExtractor() {}

    /**
     * Extraction result: paths to the .app bundle, Info.plist, and the primary Mach-O executable.
     */
    public record ExtractionResult(
            Path appBundleDir,
            Path infoPlistPath,
            Path executablePath,
            String executableName
    ) {}

    /**
     * Extracts all IPA contents into {@code workDir}, locates the .app bundle,
     * parses Info.plist, and resolves the Mach-O binary path.
     *
     * @param ipaPath  validated path to the .ipa file
     * @param workDir  empty directory to receive extracted contents
     */
    public static ExtractionResult extract(Path ipaPath, Path workDir) throws Exception {
        log.info("Extracting IPA: {} → {}", ipaPath, workDir);
        unzip(ipaPath, workDir);

        Path payloadDir = workDir.resolve("Payload");
        if (!Files.isDirectory(payloadDir))
            throw new IllegalArgumentException("IPA missing Payload/ directory");

        Path appBundle = findAppBundle(payloadDir);
        Path infoPlist = appBundle.resolve("Info.plist");
        if (!Files.exists(infoPlist))
            throw new IllegalArgumentException("Info.plist not found inside: " + appBundle);

        InfoPlist info = InfoPlist.parse(infoPlist);
        String execName = info.getExecutableName();
        if (execName == null || execName.isBlank())
            throw new IllegalArgumentException("CFBundleExecutable is empty in Info.plist");

        Path execPath = appBundle.resolve(execName);
        if (!Files.exists(execPath))
            throw new IllegalArgumentException("Executable not found: " + execPath);

        log.info("Found executable: {} ({})", execName, execPath);
        return new ExtractionResult(appBundle, infoPlist, execPath, execName);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private static void unzip(Path zip, Path destDir) throws IOException {
        try (InputStream fis = Files.newInputStream(zip);
             ZipInputStream zis = new ZipInputStream(fis)) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                Path target = destDir.resolve(entry.getName()).normalize();
                if (!target.startsWith(destDir))
                    throw new SecurityException("Zip path traversal attempt: " + entry.getName());

                if (entry.isDirectory()) {
                    Files.createDirectories(target);
                } else {
                    Files.createDirectories(target.getParent());
                    Files.copy(zis, target, StandardCopyOption.REPLACE_EXISTING);
                }
                zis.closeEntry();
            }
        }
        log.info("IPA extracted to {}", destDir);
    }

    private static Path findAppBundle(Path payloadDir) throws IOException {
        try (var stream = Files.list(payloadDir)) {
            return stream
                    .filter(p -> p.getFileName().toString().endsWith(".app"))
                    .findFirst()
                    .orElseThrow(() -> new IllegalArgumentException(
                            "No .app bundle found inside Payload/"));
        }
    }
}
