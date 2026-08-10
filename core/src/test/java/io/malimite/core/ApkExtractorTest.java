package io.malimite.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ApkExtractorTest {

    @TempDir Path tmp;

    @Test
    void extractsDexAndNativeLibs() throws Exception {
        Path apk = tmp.resolve("app.apk");
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(apk))) {
            put(zos, "AndroidManifest.xml", "<manifest/>");
            put(zos, "classes.dex", "dex");
            put(zos, "lib/arm64-v8a/libnative.so", "so");
            put(zos, "assets/config.json", "{}");
            put(zos, "res/xml/network_security_config.xml", "<network-security-config/>");
        }
        Path work = tmp.resolve("out");
        ApkExtractor.ExtractionResult r = ApkExtractor.extract(apk, work);
        assertTrue(Files.exists(r.manifestPath()));
        assertEquals(1, r.dexFiles().size());
        assertEquals(1, r.nativeLibs().size());
        assertTrue(r.assetsDir() != null);
        assertTrue(r.resDir() != null);
        assertEquals(1, ApkExtractor.preferArm64NativeLibs(r.nativeLibs()).size());
        assertEquals(List.of("arm64-v8a"), ApkExtractor.detectAbis(r.nativeLibs()));
    }

    @Test
    void preferArm64IgnoresOtherAbis() throws Exception {
        Path apk = tmp.resolve("multi.apk");
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(apk))) {
            put(zos, "AndroidManifest.xml", "<manifest/>");
            put(zos, "classes.dex", "dex");
            put(zos, "lib/armeabi-v7a/libold.so", "v7");
            put(zos, "lib/x86_64/libx.so", "x86");
            put(zos, "lib/arm64-v8a/libapp.so", "a64");
            put(zos, "lib/arm64-v8a/libother.so", "a64b");
        }
        ApkExtractor.ExtractionResult r = ApkExtractor.extract(apk, tmp.resolve("multi-out"));
        assertEquals(4, r.nativeLibs().size());
        var arm64 = ApkExtractor.preferArm64NativeLibs(r.nativeLibs());
        assertEquals(2, arm64.size());
        assertTrue(arm64.stream().allMatch(p -> p.toString().contains("/lib/arm64-v8a/")));
        assertTrue(ApkExtractor.detectAbis(r.nativeLibs()).containsAll(
                List.of("arm64-v8a", "armeabi-v7a", "x86_64")));
    }

    @Test
    void preferArm64EmptyWhenOnlyOtherAbis() throws Exception {
        Path apk = tmp.resolve("v7only.apk");
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(apk))) {
            put(zos, "AndroidManifest.xml", "<manifest/>");
            put(zos, "classes.dex", "dex");
            put(zos, "lib/armeabi-v7a/libold.so", "v7");
        }
        ApkExtractor.ExtractionResult r = ApkExtractor.extract(apk, tmp.resolve("v7-out"));
        assertTrue(ApkExtractor.preferArm64NativeLibs(r.nativeLibs()).isEmpty());
    }

    private static void put(ZipOutputStream zos, String name, String body) throws IOException {
        zos.putNextEntry(new ZipEntry(name));
        zos.write(body.getBytes());
        zos.closeEntry();
    }
}
