package io.malimite.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ApkValidatorTest {

    @TempDir Path tmp;

    @Test
    void acceptsMinimalApkZip() throws Exception {
        Path apk = tmp.resolve("tiny.apk");
        writeZip(apk, "AndroidManifest.xml", "classes.dex");
        assertDoesNotThrow(() -> ApkValidator.validate(apk));
    }

    @Test
    void acceptsMultiDex() throws Exception {
        Path apk = tmp.resolve("multidex.apk");
        writeZip(apk, "AndroidManifest.xml", "classes.dex", "classes2.dex");
        assertDoesNotThrow(() -> ApkValidator.validate(apk));
    }

    @Test
    void rejectsMissingManifest() throws Exception {
        Path apk = tmp.resolve("bad.apk");
        writeZip(apk, "classes.dex");
        IOException ex = assertThrows(IOException.class, () -> ApkValidator.validate(apk));
        assertTrue(ex.getMessage().contains("AndroidManifest"));
    }

    @Test
    void rejectsMissingDex() throws Exception {
        Path apk = tmp.resolve("nodex.apk");
        writeZip(apk, "AndroidManifest.xml");
        IOException ex = assertThrows(IOException.class, () -> ApkValidator.validate(apk));
        assertTrue(ex.getMessage().toLowerCase().contains("classes.dex"));
    }

    @Test
    void packagePlatformDetectsApk() throws Exception {
        Path apk = tmp.resolve("app.apk");
        writeZip(apk, "AndroidManifest.xml", "classes.dex");
        assertTrue(PackagePlatform.detect(apk) == PackagePlatform.ANDROID);
    }

    private static void writeZip(Path zip, String... entries) throws IOException {
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(zip))) {
            for (String name : entries) {
                zos.putNextEntry(new ZipEntry(name));
                zos.write(("content-of-" + name).getBytes());
                zos.closeEntry();
            }
        }
    }
}
