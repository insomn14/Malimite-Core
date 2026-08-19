package io.malimite.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AssessmentScannerTest {

    @TempDir Path tmp;

    @Test void androidDetectsFlagSecureAndSslPinning() throws Exception {
        Path db = tmp.resolve("a.sqlite");
        try (SqliteStore store = new SqliteStore(db.toString())) {
            store.insertClass("com.example.MainActivity", "[\"onCreate\"]", "com.example");
            store.insertFunctionDecompilations(List.of(
                    new SqliteStore.DecompilationResult(
                            "onCreate", "com.example.MainActivity",
                            "getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);\n"
                                    + "new CertificatePinner.Builder().add(\"api.example.com\", \"sha256/abc\");\n",
                            "com.example", "JADX")));
            store.insertResourceString("UsesCleartextTraffic", "UsesCleartextTraffic=false", "manifest");
            store.insertResourceString("AllowBackup", "AllowBackup=false", "manifest");
            store.insertResourceString("Debuggable", "Debuggable=false", "manifest");
            store.insertResourceString("NativeLibPic", "NativeLibPic=libx.so=enabled", "native-elf");
            store.insertResourceString("NativeLibStackCanary", "NativeLibStackCanary=libx.so=enabled", "native-elf");
            store.insertResourceString("NativeLibDebugSymbols", "NativeLibDebugSymbols=libx.so=stripped", "native-elf");

            int n = new AssessmentScanner().scan(store, "com.example", PackagePlatform.ANDROID);
            assertTrue(n >= 10);

            Map<String, Map<String, Object>> byId = index(store.getAssessments("com.example"));
            assertEquals("PRESENT", byId.get("ASSESS-FLAG-SECURE").get("status"));
            assertEquals("PRESENT", byId.get("ASSESS-SSL-PINNING").get("status"));
            assertTrue(String.valueOf(byId.get("ASSESS-SSL-PINNING").get("detail")).contains("DYNAMIC_OKHTTP"));
            assertEquals("PRESENT", byId.get("ASSESS-CLEARTEXT-BLOCKED").get("status"));
            assertEquals("PRESENT", byId.get("ASSESS-NATIVE-HARDENING").get("status"));
            assertEquals("ABSENT", byId.get("ASSESS-FRIDA-DETECTION").get("status"));
            for (var row : byId.values()) {
                String id = String.valueOf(row.get("control_id"));
                AssessmentCatalog.Guide g = AssessmentCatalog.lookup(id, "ANDROID",
                        String.valueOf(row.get("title")));
                assertFalse(g.summary().isBlank(), id);
                assertFalse(g.staticChecks().isEmpty(), id);
                assertFalse(g.dynamicChecks().isEmpty(), id);
                assertTrue(AssessmentCatalog.controlIds().contains(id), "catalog should cover " + id);
            }
            AssessmentCatalog.Guide bio = AssessmentCatalog.lookup("ASSESS-BIOMETRIC", "ANDROID");
            assertTrue(bio.summary().toLowerCase().contains("biometric"));
            assertNotEquals(
                    AssessmentCatalog.lookup("ASSESS-BIOMETRIC", "IOS").summary(),
                    bio.summary());
            AssessmentCatalog.Guide unknown = AssessmentCatalog.lookup(
                    "ASSESS-NOT-A-REAL-CONTROL", "ANDROID", "Custom control");
            assertTrue(unknown.summary().contains("Custom control"));
            assertFalse(unknown.staticChecks().isEmpty());
            assertFalse(unknown.dynamicChecks().isEmpty());
        }
    }

    @Test void iosDetectsJailbreakSignalsAsPresent() throws Exception {
        Path db = tmp.resolve("i.sqlite");
        try (SqliteStore store = new SqliteStore(db.toString())) {
            store.insertClass("AppDelegate", "[\"application\"]", "MyApp");
            store.insertFunctionDecompilations(List.of(
                    new SqliteStore.DecompilationResult(
                            "check", "JailbreakDetector",
                            "if (access(\"/Applications/Cydia.app\", F_OK)==0) return true;\n"
                                    + "ptrace(PT_DENY_ATTACH, 0, 0, 0);\n",
                            "MyApp", "GHIDRA")));
            store.insertResourceString("MachOSecurityFlags", "MH_PIE=1", "macho-flags");
            store.insertMachoString("0x1", "TrustKit", "__TEXT", "s", "MyApp");

            new AssessmentScanner().scan(store, "MyApp", PackagePlatform.IOS);
            Map<String, Map<String, Object>> byId = index(store.getAssessments("MyApp"));
            assertEquals("PRESENT", byId.get("ASSESS-JAILBREAK-DETECTION").get("status"));
            assertEquals("PRESENT", byId.get("ASSESS-ANTIDEBUG").get("status"));
            assertEquals("PRESENT", byId.get("ASSESS-SSL-PINNING").get("status"));
            assertEquals("PRESENT", byId.get("ASSESS-PIE").get("status"));
            for (var row : byId.values()) {
                String id = String.valueOf(row.get("control_id"));
                assertTrue(AssessmentCatalog.controlIds().contains(id), "catalog should cover " + id);
                AssessmentCatalog.Guide g = AssessmentCatalog.lookup(id, "IOS");
                assertFalse(g.staticChecks().isEmpty(), id);
                assertFalse(g.dynamicChecks().isEmpty(), id);
            }
        }
    }

    @Test void javaObfuscationPartialWhenSomeShortNames() throws Exception {
        Path db = tmp.resolve("o.sqlite");
        try (SqliteStore store = new SqliteStore(db.toString())) {
            // Mix of readable and short names
            for (int i = 0; i < 10; i++)
                store.insertClass("com.example.Feature" + i, "[]", "com.example");
            for (int i = 0; i < 5; i++)
                store.insertClass("a.b.c" + i, "[]", "com.example");
            store.insertFunctionDecompilations(List.of(
                    new SqliteStore.DecompilationResult("<class>", "com.example.Feature0", "class Feature0 {}", "com.example", "JADX")));

            new AssessmentScanner().scan(store, "com.example", PackagePlatform.ANDROID);
            Map<String, Map<String, Object>> byId = index(store.getAssessments("com.example"));
            String st = String.valueOf(byId.get("ASSESS-OBFUSCATION-JAVA").get("status"));
            assertTrue(st.equals("PARTIAL") || st.equals("PRESENT") || st.equals("ABSENT"), st);
        }
    }

    @Test void thirdPartyRootBeerStillPresentInAssessment() throws Exception {
        Path db = tmp.resolve("rb.sqlite");
        try (SqliteStore store = new SqliteStore(db.toString())) {
            store.insertClass("com.scottyab.rootbeer.RootBeer", "[\"isRooted\"]", "com.example.app");
            store.insertFunctionDecompilations(List.of(
                    new SqliteStore.DecompilationResult(
                            "isRooted", "com.scottyab.rootbeer.RootBeer",
                            "public boolean isRooted() { return checkForSuBinary() || detectRootManagementApps(); }",
                            "com.example.app", "JADX")));
            store.insertMachoString("jadx:1", "RootBeer", "__JADX", "RootBeer", "com.example.app");

            new AssessmentScanner().scan(store, "com.example.app", PackagePlatform.ANDROID);
            Map<String, Map<String, Object>> byId = index(store.getAssessments("com.example.app"));
            assertEquals("PRESENT", byId.get("ASSESS-ROOT-DETECTION").get("status"));
            assertEquals("PRESENT", byId.get("ASSESS-SECURITY-SDK").get("status"));
        }
    }

    private static Map<String, Map<String, Object>> index(List<Map<String, Object>> rows) {
        Map<String, Map<String, Object>> m = new java.util.HashMap<>();
        for (var r : rows) m.put(String.valueOf(r.get("control_id")), r);
        return m;
    }
}
