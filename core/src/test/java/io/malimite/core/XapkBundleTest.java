package io.malimite.core;

import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class XapkBundleTest {

    @TempDir Path tmp;

    // ── helpers ───────────────────────────────────────────────────────────────────────────────────────────────────

    private static byte[] zip(Map<String, byte[]> entries) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ZipOutputStream z = new ZipOutputStream(bos)) {
            for (var e : entries.entrySet()) {
                z.putNextEntry(new ZipEntry(e.getKey()));
                z.write(e.getValue());
                z.closeEntry();
            }
        }
        return bos.toByteArray();
    }

    private static Map<String, byte[]> files(String... kv) {
        Map<String, byte[]> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put(kv[i], kv[i + 1].getBytes(StandardCharsets.UTF_8));
        return m;
    }

    private Path bundle(String name, Map<String, byte[]> apks) throws IOException {
        Path p = tmp.resolve(name);
        Files.write(p, zip(apks));
        return p;
    }

    private static List<String> names(Path zipFile) throws IOException {
        List<String> out = new ArrayList<>();
        try (ZipFile z = new ZipFile(zipFile.toFile())) {
            z.stream().forEach(e -> out.add(e.getName()));
        }
        return out;
    }

    private static String read(Path zipFile, String entry) throws IOException {
        try (ZipFile z = new ZipFile(zipFile.toFile())) {
            return new String(z.getInputStream(z.getEntry(entry)).readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private Map<String, byte[]> typicalBundle() throws IOException {
        Map<String, byte[]> m = new LinkedHashMap<>();
        m.put("base.apk", zip(files("AndroidManifest.xml", "BASE-MANIFEST", "classes.dex", "dex1", "resources.arsc", "BASE-ARSC",
                "res/a.png", "a")));
        m.put("split_config.arm64_v8a.apk", zip(files("AndroidManifest.xml", "SPLIT-MANIFEST", "resources.arsc", "SPLIT-ARSC",
                "META-INF/CERT.RSA", "sig", "lib/arm64-v8a/libx.so", "ELF")));
        m.put("split_config.xhdpi.apk", zip(files("AndroidManifest.xml", "SPLIT2", "res/drawable-xhdpi/b.png", "b")));
        return m;
    }

    // ── merging ───────────────────────────────────────────────────────────────────────────────────────────────────

    @Test
    void nativeLibsFromSplitsEndUpInTheMergedApkAndSplitMetadataDoesNot() throws Exception {
        Path in = bundle("app.xapk", typicalBundle());
        Path out = tmp.resolve("out.merged.apk");
        var m = XapkBundle.merge(in, out);

        assertEquals("base.apk", m.base());
        assertEquals(List.of("split_config.arm64_v8a.apk", "split_config.xhdpi.apk"), m.splits());
        var n = names(out);
        assertTrue(n.containsAll(List.of("AndroidManifest.xml", "classes.dex", "resources.arsc", "res/a.png",
                "lib/arm64-v8a/libx.so", "res/drawable-xhdpi/b.png")), n.toString());
        assertEquals("BASE-MANIFEST", read(out, "AndroidManifest.xml"), "the base manifest describes the app");
        assertEquals("BASE-ARSC", read(out, "resources.arsc"));
        assertFalse(n.contains("META-INF/CERT.RSA"), "split signatures are dropped");
        assertEquals(n.size(), n.stream().distinct().count(), "no duplicate entries");

        // the rest of the pipeline sees an ordinary APK with the arm64 library in it
        ApkValidator.validate(out);
        var ex = ApkExtractor.extract(out, tmp.resolve("x"));
        assertEquals(1, ApkExtractor.preferArm64NativeLibs(ex.nativeLibs()).size());
    }

    @Test
    void mergedOutputIsDeterministic() throws Exception {
        Path in = bundle("app.xapk", typicalBundle());
        var a = names(XapkBundle.merge(in, tmp.resolve("a.apk")).apk());
        var b = names(XapkBundle.merge(in, tmp.resolve("b.apk")).apk());
        assertEquals(a, b);
    }

    @Test
    void featureSplitsWithCodeContinueTheDexNumbering() throws Exception {
        Map<String, byte[]> m = new LinkedHashMap<>();
        m.put("base.apk", zip(files("AndroidManifest.xml", "m", "classes.dex", "d1", "classes2.dex", "d2")));
        m.put("split_feature.apk", zip(files("AndroidManifest.xml", "m", "classes.dex", "FEATURE")));
        var out = XapkBundle.merge(bundle("f.xapk", m), tmp.resolve("o.apk")).apk();
        assertEquals("d1", read(out, "classes.dex"), "base code is untouched");
        assertEquals("FEATURE", read(out, "classes3.dex"), "feature code is added, not lost or overwritten");
        ApkValidator.validate(out);
    }

    @Test
    void onNameCollisionsTheBaseWins() throws Exception {
        Map<String, byte[]> m = new LinkedHashMap<>();
        m.put("base.apk", zip(files("AndroidManifest.xml", "m", "classes.dex", "d", "assets/x.txt", "BASE")));
        m.put("split_assets.apk", zip(files("AndroidManifest.xml", "m", "assets/x.txt", "SPLIT", "assets/y.txt", "y")));
        var out = XapkBundle.merge(bundle("c.xapk", m), tmp.resolve("o.apk")).apk();
        assertEquals("BASE", read(out, "assets/x.txt"));
        assertEquals("y", read(out, "assets/y.txt"));
    }

    @Test
    void obbExpansionsAndOtherFilesAreNeverMerged() throws Exception {
        Map<String, byte[]> m = typicalBundle();
        m.put("Android/obb/com.x/main.1.com.x.obb", "HUGE".getBytes());
        m.put("icon.png", "png".getBytes());
        var out = XapkBundle.merge(bundle("o.xapk", m), tmp.resolve("o.apk")).apk();
        assertTrue(names(out).stream().noneMatch(n -> n.contains("obb") || n.equals("icon.png")), names(out).toString());
    }

    @Test
    void aSingleApkBundleStillWorks() throws Exception {
        Map<String, byte[]> m = new LinkedHashMap<>();
        m.put("only.apk", zip(files("AndroidManifest.xml", "m", "classes.dex", "d")));
        var r = XapkBundle.merge(bundle("s.xapk", m), tmp.resolve("o.apk"));
        assertEquals("only.apk", r.base());
        assertEquals(List.of(), r.splits());
    }

    // ── choosing the base ─────────────────────────────────────────────────────────────────────────────────────────

    @Test
    void manifestJsonNamesTheBaseEvenWhenItIsNotCalledBase() throws Exception {
        Map<String, byte[]> m = new LinkedHashMap<>();
        m.put("com.x.app.apk", zip(files("AndroidManifest.xml", "m", "classes.dex", "d")));
        m.put("config.arm64_v8a.apk", zip(files("AndroidManifest.xml", "m", "lib/arm64-v8a/liby.so", "e")));
        m.put("manifest.json", new JSONObject().put("package_name", "com.x.app")
                .put("split_apks", new org.json.JSONArray()
                        .put(new JSONObject().put("file", "com.x.app.apk").put("id", "base"))
                        .put(new JSONObject().put("file", "config.arm64_v8a.apk").put("id", "config.arm64_v8a")))
                .toString().getBytes());
        var r = XapkBundle.merge(bundle("j.xapk", m), tmp.resolve("o.apk"));
        assertEquals("com.x.app.apk", r.base());
        assertTrue(names(r.apk()).contains("lib/arm64-v8a/liby.so"));
    }

    @Test
    void aBrokenManifestJsonFallsBackToTheFileNames() throws Exception {
        Map<String, byte[]> m = typicalBundle();
        m.put("manifest.json", "{not json".getBytes());
        assertEquals("base.apk", XapkBundle.merge(bundle("b.xapk", m), tmp.resolve("o.apk")).base());
    }

    @Test
    void baseIsFoundByNameConventions() {
        assertEquals(1, XapkBundle.chooseBase(List.of("split_a.apk", "base.apk"), null, i -> null));
        assertEquals(0, XapkBundle.chooseBase(List.of("splits/base-master.apk", "splits/base-xhdpi.apk"), null, i -> null));
        assertEquals(0, XapkBundle.chooseBase(List.of("com.x.apk", "config.arm64_v8a.apk", "split_config.en.apk"), null, i -> null));
        // the APK's own manifest wins over a misleading file name
        assertEquals(1, XapkBundle.chooseBase(List.of("a.apk", "b.apk"), null, i -> i == 0));
    }

    @Test
    void anAmbiguousBundleIsRefusedWithTheCandidates() {
        var ex = assertThrows(IllegalArgumentException.class,
                () -> XapkBundle.chooseBase(List.of("one.apk", "two.apk"), null, i -> null));
        assertTrue(ex.getMessage().contains("one.apk") && ex.getMessage().contains("two.apk"), ex.getMessage());
    }

    @Test
    void splitNamesAreRecognised() {
        for (String s : new String[] {"split_config.arm64_v8a.apk", "config.xhdpi.apk", "x/split-feature.apk", "app.config.en.apk"})
            assertTrue(XapkBundle.looksLikeSplitName(s), s);
        for (String s : new String[] {"base.apk", "com.x.app.apk", "app.apk"})
            assertFalse(XapkBundle.looksLikeSplitName(s), s);
    }

    // ── hostile input ─────────────────────────────────────────────────────────────────────────────────────────────

    @Test
    void entryNamesThatCouldEscapeADirectoryAreRejected() throws Exception {
        for (String evil : new String[] {"../evil.so", "lib/../../evil", "/abs/path", "lib\\x.so"}) {
            Map<String, byte[]> m = new LinkedHashMap<>();
            m.put("base.apk", zip(files("AndroidManifest.xml", "m", "classes.dex", "d", evil, "x")));
            var ex = assertThrows(IOException.class, () -> XapkBundle.merge(bundle("z.xapk", m), tmp.resolve("o.apk")), evil);
            assertTrue(ex.getMessage().contains("Unsafe entry name"), ex.getMessage());
        }
        Map<String, byte[]> outer = new LinkedHashMap<>();
        outer.put("../base.apk", zip(files("AndroidManifest.xml", "m", "classes.dex", "d")));
        assertThrows(IOException.class, () -> XapkBundle.merge(bundle("z2.xapk", outer), tmp.resolve("o2.apk")));
    }

    @Test
    void theSizeLimitIsEnforcedWhileCopyingNotJustFromDeclaredSizes() throws Exception {
        byte[] zeros = new byte[3 * 1024 * 1024];   // compresses to a few KB: a small bundle that inflates a lot
        Map<String, byte[]> m = new LinkedHashMap<>();
        m.put("base.apk", zip(Map.of("AndroidManifest.xml", "m".getBytes(), "classes.dex", "d".getBytes(), "assets/big.bin", zeros)));
        Path in = bundle("big.xapk", m);
        assertTrue(Files.size(in) < 100_000, "the bundle itself is small");
        assertThrows(IOException.class, () -> XapkBundle.merge(in, tmp.resolve("o.apk"), 1024 * 1024));
        assertDoesNotThrow(() -> XapkBundle.merge(in, tmp.resolve("o2.apk"), 64L * 1024 * 1024));
    }

    @Test
    void aBundleWithoutApksIsRejected() throws Exception {
        Path in = bundle("empty.xapk", files("manifest.json", "{}", "icon.png", "x"));
        assertThrows(IOException.class, () -> XapkBundle.merge(in, tmp.resolve("o.apk")));
    }

    // ── recognising bundles ───────────────────────────────────────────────────────────────────────────────────────

    @Test
    void bundlesAreToldApartFromApksAndGarbage() throws Exception {
        assertTrue(XapkBundle.isBundle(bundle("a.xapk", typicalBundle())));
        Path apk = tmp.resolve("plain.apk");
        Files.write(apk, zip(files("AndroidManifest.xml", "m", "classes.dex", "d", "assets/inner.apk", "x")));
        assertFalse(XapkBundle.isBundle(apk), "an APK that merely contains an .apk file is still an APK");
        Path junk = tmp.resolve("junk.xapk");
        Files.writeString(junk, "not a zip at all");
        assertFalse(XapkBundle.isBundle(junk));
        assertFalse(XapkBundle.isBundle(bundle("docs.zip", files("readme.txt", "hi"))));
        assertFalse(XapkBundle.isBundle(tmp.resolve("missing.xapk")));
    }

    @Test
    void xapkIsAnAndroidPackageByExtensionAndByContent() throws Exception {
        assertEquals(PackagePlatform.ANDROID, PackagePlatform.detect(bundle("app.xapk", typicalBundle())));
        assertEquals(PackagePlatform.ANDROID, PackagePlatform.detect(bundle("app.XAPK", typicalBundle())));
        assertEquals(PackagePlatform.ANDROID, PackagePlatform.detect(bundle("app.zip", typicalBundle())), "sniffed from content");
        assertThrows(IOException.class, () -> PackagePlatform.detect(bundle("docs.zip", files("readme.txt", "hi"))));
    }

    @Test
    void manifestOnlyParsingGivesUpCleanlyOnThingsThatAreNotApks() throws Exception {
        assertNull(AndroidManifestParser.parseManifestWithoutResources(tmp.resolve("missing.apk")));
        Path noManifest = tmp.resolve("n.apk");
        Files.write(noManifest, zip(files("classes.dex", "d")));
        assertNull(AndroidManifestParser.parseManifestWithoutResources(noManifest));
        Path garbage = tmp.resolve("g.apk");
        Files.write(garbage, zip(files("AndroidManifest.xml", "this is not binary xml")));
        assertNull(AndroidManifestParser.parseManifestWithoutResources(garbage));
    }

    @Test
    void analyzeOptionsCanBeRepointedAtTheMergedApk() {
        var o = AnalyzeOptions.builder().packagePath(Path.of("a.xapk")).outputDir(Path.of("out")).decompiler("asc")
                .maxAscClasses(7).build();
        var p = o.withPackagePath(Path.of("out/a.merged.apk"));
        assertEquals(Path.of("out/a.merged.apk"), p.packagePath());
        assertEquals(Path.of("out"), p.outputDir());
        assertTrue(p.useAsc());
        assertEquals(7, p.maxAscClasses());
    }

    // ── a real bundle, when one is supplied ───────────────────────────────────────────────────────────────────────

    @Test
    @EnabledIfEnvironmentVariable(named = "MALIMITE_TEST_XAPK", matches = ".+")
    void aRealXapkMergesIntoAValidApkWithItsNativeLibraries() throws Exception {
        Path real = Path.of(System.getenv("MALIMITE_TEST_XAPK"));
        assertTrue(XapkBundle.isBundle(real));
        var m = XapkBundle.merge(real, tmp.resolve("real.merged.apk"));
        ApkValidator.validate(m.apk());
        var meta = AndroidManifestParser.parse(m.apk());
        assertNotNull(meta.applicationId());
        assertNotEquals("unknown", meta.applicationId());
        assertNotNull(meta.versionName());
        // the manifest alone is enough, even when apk-parser cannot read this app's resources.arsc
        var alone = AndroidManifestParser.parseManifestWithoutResources(m.apk());
        assertNotNull(alone, "manifest-only parsing must work on a real manifest");
        assertEquals(meta.applicationId(), alone.applicationId());
        assertEquals(meta.versionName(), alone.versionName());
        System.out.println("real bundle: base=" + m.base() + " splits=" + m.splits() + " app=" + meta.applicationId()
                + " v" + meta.versionName());
    }
}
