package io.malimite.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/** Platform / origin prompt selection, envelope, and cache-key tests (no network). */
class LlmEnricherPromptTest {

    static final class CapturingProvider implements LlmProvider {
        String system;
        String user;
        @Override
        public String complete(String systemPrompt, String userMessage) {
            this.system = systemPrompt;
            this.user = userMessage;
            return "{\"vulnerabilities\":[]}";
        }
    }

    static final class MemoryCache implements LlmCache {
        final List<String> keys = new ArrayList<>();
        @Override public Optional<String> get(String hash) { return Optional.empty(); }
        @Override public void put(String hash, String value) { keys.add(hash); }
    }

    @Test void iosAutoFixUsesSwiftOrObjC() {
        var swift = new LlmEnricher(null, LlmMode.AUTO_FIX, null, true, PackagePlatform.IOS);
        assertTrue(swift.buildSystemPrompt("GHIDRA").contains("idiomatic Swift"));

        var objc = new LlmEnricher(null, LlmMode.AUTO_FIX, null, false, PackagePlatform.IOS);
        assertTrue(objc.buildSystemPrompt("GHIDRA").contains("idiomatic Objective-C"));
        assertFalse(objc.buildSystemPrompt("GHIDRA").contains("JADX"));
    }

    @Test void androidJadxPromptsAreJavaNotIos() {
        var e = new LlmEnricher(null, LlmMode.SUMMARIZE, null, false, PackagePlatform.ANDROID);
        String p = e.buildSystemPrompt("JADX");
        assertTrue(p.contains("Android"));
        assertTrue(p.contains("JADX"));
        assertFalse(p.contains("iOS"));

        var fix = new LlmEnricher(null, LlmMode.AUTO_FIX, null, false, PackagePlatform.ANDROID);
        assertTrue(fix.buildSystemPrompt("JADX").contains("Java"));
        assertFalse(fix.buildSystemPrompt("JADX").contains("Objective-C"));
    }

    @Test void androidNativePromptsUseGhidraSo() {
        var e = new LlmEnricher(null, LlmMode.FIND_VULNS, null, false, PackagePlatform.ANDROID);
        String p = e.buildSystemPrompt("GHIDRA");
        assertTrue(p.contains("native"));
        assertTrue(p.contains(".so") || p.contains("JNI"));
        assertFalse(p.contains("Keychain") || p.contains("kSecAttrAccessible"));
    }

    @Test void androidFindVulnsJadxMentionsJavaApis() {
        var e = new LlmEnricher(null, LlmMode.FIND_VULNS, null, false, PackagePlatform.ANDROID);
        String p = e.buildSystemPrompt("JADX");
        assertTrue(p.contains("JADX"));
        assertTrue(p.contains("execSQL") || p.contains("addJavascriptInterface"));
        assertFalse(p.contains("PTR_s_"));
    }

    @Test void userEnvelopeIncludesMetadata() {
        var e = new LlmEnricher(null, LlmMode.SUMMARIZE, null, false, PackagePlatform.ANDROID);
        var fn = new SqliteStore.DecompilationResult(
                "onCreate", "com.example.MainActivity", "void onCreate() {}", "com.example", "JADX");
        String msg = e.buildUserMessage(fn, "JADX");
        assertTrue(msg.contains("platform: ANDROID"));
        assertTrue(msg.contains("decompiler: JADX"));
        assertTrue(msg.contains("language_hint: Java"));
        assertTrue(msg.contains("class: com.example.MainActivity"));
        assertTrue(msg.contains("function: onCreate"));
        assertTrue(msg.contains("```java"));
        assertTrue(msg.contains("void onCreate() {}"));
    }

    @Test void cacheKeyDiffersByPlatformAndOrigin() {
        String code = "int x = 1;";
        String ios = LlmEnricher.cacheKey(code, LlmMode.SUMMARIZE, PackagePlatform.IOS, "GHIDRA");
        String andJ = LlmEnricher.cacheKey(code, LlmMode.SUMMARIZE, PackagePlatform.ANDROID, "JADX");
        String andN = LlmEnricher.cacheKey(code, LlmMode.SUMMARIZE, PackagePlatform.ANDROID, "GHIDRA");
        assertNotEquals(ios, andJ);
        assertNotEquals(andJ, andN);
        assertNotEquals(ios, andN);
    }

    @Test void enrichSendsEnvelopeAndUsesV5Cache(@TempDir Path tmp) throws Exception {
        CapturingProvider provider = new CapturingProvider();
        MemoryCache cache = new MemoryCache();
        Path db = tmp.resolve("t.sqlite");
        try (SqliteStore store = new SqliteStore(db.toString())) {
            store.insertFunctionDecompilations(List.of(new SqliteStore.DecompilationResult(
                    "foo", "com.app.A", "public void foo() { Log.d(\"t\", secret); }", "com.app", "JADX")));
            new LlmEnricher(provider, LlmMode.SUMMARIZE, cache, false, PackagePlatform.ANDROID,
                    new LearnedRulesStore(tmp.resolve("rules.json")))
                    .enrich(store, "com.app");
        }
        assertNotNull(provider.system);
        assertTrue(provider.system.contains("Android"));
        assertTrue(provider.user.contains("platform: ANDROID"));
        assertTrue(provider.user.contains("decompiler: JADX"));
        assertEquals(1, cache.keys.size());
        String expected = LlmEnricher.cacheKey(
                "public void foo() { Log.d(\"t\", secret); }",
                LlmMode.SUMMARIZE, PackagePlatform.ANDROID, "JADX");
        assertEquals(expected, cache.keys.get(0));
        assertTrue(LlmEnricher.PROMPT_VERSION.equals("v6"));
    }
}
