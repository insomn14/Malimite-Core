package io.malimite.core;

import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class OnDemandDecompilerTest {

    @TempDir Path tmp;

    private Path scan(String platform) throws Exception {
        Files.writeString(tmp.resolve("scan.json"),
                new JSONObject().put("platform", platform).put("packagePath", "/does/not/exist.apk").toString());
        return tmp;
    }

    @Test
    void rejectsPathLikeAndMalformedClassNames() throws Exception {
        Path d = scan("ANDROID");
        for (String bad : new String[] {"../etc/passwd", "a/b", "a..b", "a b", "a;rm", "", ".a", "a."}) {
            JSONObject r = OnDemandDecompiler.run(d, "asc", bad, "");
            assertFalse(r.getBoolean("ok"), bad);
            assertTrue(r.getString("error").contains("invalid class name"), bad);
        }
    }

    @Test
    void rejectsUnknownToolAndIosScan() throws Exception {
        assertFalse(OnDemandDecompiler.run(scan("ANDROID"), "bash", "a.B", "").getBoolean("ok"));
        JSONObject r = OnDemandDecompiler.run(scan("IOS"), "jadx", "a.B", "");
        assertFalse(r.getBoolean("ok"));
        assertTrue(r.getString("error").contains("only supports Android"));
    }

    @Test
    void packagePathFallsBackToUploadNextToScanJson() throws Exception {
        Path up = Files.writeString(tmp.resolve("upload.apk"), "x");
        assertEquals(up, OnDemandDecompiler.packagePath(tmp, new JSONObject().put("packagePath", "/nope.apk")));
        Files.delete(up);
        assertThrows(IllegalStateException.class,
                () -> OnDemandDecompiler.packagePath(tmp, new JSONObject()));
    }

    @Test
    void resultShape() {
        JSONObject r = OnDemandDecompiler.result(true, "asc", "a.B", "code", "");
        assertEquals("code", r.getString("code"));
        assertTrue(r.getBoolean("ok"));
    }

    @Test
    void ghidraValidatesTargetAndRequiresLibOnAndroid() throws Exception {
        Path d = scan("ANDROID");
        for (String bad : new String[] {"main;rm -rf /", "a|b", "", "x".repeat(201), "-deleteProject", "-import", "--x"}) {
            JSONObject r = OnDemandDecompiler.run(d, "ghidra", bad, "libfoo.so");
            assertFalse(r.getBoolean("ok"), bad);
            assertTrue(r.getString("error").contains("invalid target"), bad);
        }
        JSONObject noLib = OnDemandDecompiler.run(d, "ghidra", "JNI_OnLoad", "");
        assertTrue(noLib.getString("error").contains("--lib"));
        for (String badLib : new String[] {"../x.so", "-x.so", "a/b.so", "x.so; rm"})
            assertTrue(OnDemandDecompiler.run(d, "ghidra", "JNI_OnLoad", badLib).getString("error").contains("--lib"), badLib);
    }

    @Test
    void ghidraCommandsKeepProjectAndReopenReadOnly() {
        CoreConfig cfg = new CoreConfig(Path.of("/opt/ghidra"));
        var imp = GhidraOnDemand.importCmd(cfg, Path.of("/p"), "proj", Path.of("/bin/App"));
        assertFalse(imp.contains("-deleteProject"), "persistent project must not be deleted");
        assertEquals(java.util.List.of("/opt/ghidra/support/analyzeHeadless", "/p", "proj", "-import", "/bin/App"), imp);
        // headless has no such options: 12.x would treat them as import paths, 11.x rejects them
        for (String flag : new String[] {"-enableAnalyzer", "-disableAnalyzer", "-skipAnalysisPrompt"})
            assertFalse(imp.contains(flag), flag);
        var proc = GhidraOnDemand.processCmd(cfg, Path.of("/p"), "proj", "App", Path.of("/s"), Path.of("/s/out.txt"), "main");
        assertTrue(proc.containsAll(java.util.List.of("-process", "App", "-noanalysis", "-readOnly", "DecompileOne.java", "main")));
        assertFalse(proc.contains("-import"));
    }

    @Test
    void ghidraProjectMarkerRoundTrip() throws Exception {
        assertNull(GhidraOnDemand.readMarker(tmp));
        Files.writeString(tmp.resolve(".imported"), "MyApp\n");
        assertEquals("MyApp", GhidraOnDemand.readMarker(tmp));
    }

    @Test
    void decompileOneScriptIsBundled() throws Exception {
        try (var in = GhidraOnDemand.class.getResourceAsStream("/ghidra/DecompileOne.java")) {
            assertNotNull(in);
            String src = new String(in.readAllBytes());
            assertTrue(src.contains("public class DecompileOne extends GhidraScript"));
            assertFalse(src.contains("import org.json"), "must not need json.jar inside Ghidra");
        }
    }

    @Test
    void projectKeysNeverCollideForLookalikeLibNames() {
        // sanitising alone maps all of these to "a_b.so"
        var keys = new java.util.HashSet<>(java.util.List.of(
                GhidraOnDemand.projectKey("a b.so"), GhidraOnDemand.projectKey("a+b.so"), GhidraOnDemand.projectKey("a_b.so")));
        assertEquals(3, keys.size());
        assertEquals(GhidraOnDemand.projectKey("libx.so"), GhidraOnDemand.projectKey("libx.so"));
    }

    @Test
    void failureSummaryKeepsTheRealCauseNotStackFrames() {
        var lines = java.util.List.of(
                "2026-10-11 main ERROR Could not determine local host name java.net.UnknownHostException: x",
                "\tat java.base/java.net.InetAddress.getLocalHost(InetAddress.java:1936)",
                "INFO  IMPORTING: file:///w/lib.so (HeadlessAnalyzer)",
                "ERROR Abort due to Headless analyzer error: libharfbuzz.so.0: cannot open shared object file (HeadlessAnalyzer)",
                "\tat ghidra.Ghidra.main(Ghidra.java:54)",
                "java.net.UnknownHostException: 8db509bd1fcf: Temporary failure in name resolution",
                "Caused by: java.lang.Foo", "\t... 20 more");
        String s = GhidraOnDemand.summarizeFailure(lines);
        assertTrue(s.contains("libharfbuzz.so.0"), s);
        assertFalse(s.contains("UnknownHost"), s);
        assertFalse(s.contains("Ghidra.java:54"), s);
        assertEquals("only line", GhidraOnDemand.summarizeFailure(java.util.List.of("\tat x", "only line")));
    }
}
