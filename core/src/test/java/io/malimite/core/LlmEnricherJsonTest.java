package io.malimite.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies the LLM → Vulnerabilities + LearnedRulesStore plumbing without
 * any real LLM call (a fake provider returns a canned JSON string).
 */
class LlmEnricherJsonTest {

    /** Fake provider that returns a fixed JSON response. */
    static class FakeProvider implements LlmProvider {
        private final String response;
        FakeProvider(String response) { this.response = response; }
        @Override public String complete(String systemPrompt, String userMessage) { return response; }
    }

    static class MemoryCache implements LlmCache {
        @Override public Optional<String> get(String hash) { return Optional.empty(); }
        @Override public void put(String hash, String value) { /* no-op */ }
    }

    private static final String SAMPLE_JSON = """
        {
          "vulnerabilities": [
            {
              "scope": "XSS",
              "title": "JavaScript injection via evaluateJavaScript",
              "severity": "HIGH",
              "cvss": 7.5,
              "cwe": "CWE-79",
              "description": "Token concatenated into JS string passed to evaluateJavaScript",
              "evidence": "[webView evaluateJavaScript:[NSString stringWithFormat:@\\"setToken('%@')\\", token]];",
              "poc_steps": "1. Stuff payload in token\\n2. trigger sendToken\\n3. JS runs",
              "remediation": "Use postMessage / JSON-encode the value",
              "detection_regex": "evaluateJavaScript[^)]{0,80}stringWithFormat[^)]{0,80}%@"
            },
            {
              "scope": "KEYCHAIN",
              "title": "Missing kSecAttrAccessible",
              "severity": "MEDIUM",
              "cvss": 5.3,
              "cwe": "CWE-922",
              "description": "SecItemAdd without accessibility class",
              "evidence": "SecItemAdd(query, NULL);",
              "poc_steps": "1. read backup\\n2. token accessible",
              "remediation": "Add kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
              "detection_regex": "SecItemAdd\\\\s*\\\\([^)]{0,200}\\\\)(?![^{]*kSecAttrAccessible)"
            }
          ]
        }
        """;

    @Test void parsesJsonAndPopulatesBothStores(@TempDir Path tmp) throws Exception {
        // Prepare a SQLite store with a single decompiled function
        Path dbPath = tmp.resolve("test.sqlite");
        try (SqliteStore store = new SqliteStore(dbPath.toString())) {
            // Source code must contain both regex patterns so they pass self-validation.
            // Order matches the XSS regex's expected appearance: evaluateJavaScript first,
            // then stringWithFormat with %@. Plus a SecItemAdd without kSecAttrAccessible.
            // Avoid parens between keywords because the regex uses [^)]{0,N}.
            // First line satisfies the XSS regex (avoids ')' between tokens since [^)]).
            // Second line satisfies the KEYCHAIN regex which requires SecItemAdd(...) parens.
            String src =
                "  evaluateJavaScript x stringWithFormat %@ END\n" +
                "  SecItemAdd(query, NULL); END";
            store.insertFunctionDecompilations(List.of(new SqliteStore.DecompilationResult(
                    "sendToken", "WebViewController", src, "MyApp")));

            // Use a fresh LearnedRulesStore at a temp path
            Path rulesPath = tmp.resolve("learned_rules.json");
            LearnedRulesStore rulesStore = new LearnedRulesStore(rulesPath);

            // Run enricher with the fake provider
            new LlmEnricher(new FakeProvider(SAMPLE_JSON), LlmMode.FIND_VULNS,
                    new MemoryCache(), false, rulesStore)
                    .enrich(store, "MyApp");

            // Verify 2 vulnerabilities inserted
            List<java.util.Map<String, Object>> vulns = store.getVulnerabilities("MyApp");
            assertEquals(2, vulns.size(), "should insert one vulnerability per JSON entry");

            // Verify rule IDs follow LLM-{SCOPE}-{NNN}
            boolean hasXss     = vulns.stream().anyMatch(v -> v.get("rule_id").toString().startsWith("LLM-XSS-"));
            boolean hasKeychain = vulns.stream().anyMatch(v -> v.get("rule_id").toString().startsWith("LLM-KEYCHAIN-"));
            assertTrue(hasXss,      "expected LLM-XSS-* rule id");
            assertTrue(hasKeychain, "expected LLM-KEYCHAIN-* rule id");

            // Verify rules persisted to LearnedRulesStore
            assertEquals(2, rulesStore.size(), "expected 2 rules persisted to disk");

            // Reload from disk → still 2 rules
            LearnedRulesStore reloaded = new LearnedRulesStore(rulesPath);
            assertEquals(2, reloaded.size(), "rules should persist across reload");
            assertEquals(2, reloaded.asVulnerabilityRules().size(), "should produce 2 compilable rules");
        }
    }

    @Test void rejectsPlaceholderRegexAndSanitizesEllipsisFields(@TempDir Path tmp) throws Exception {
        String sourceCode =
            "void invokeSuspend() {\n" +
            "  this.$assetManager.open(this.$fileName);\n" +
            "  new FileOutputStream(this.$outFile);\n" +
            "}";
        String llmJson = """
            {
              "vulnerabilities": [
                {
                  "scope": "PATH-TRAVERSAL",
                  "title": "Unsanitized asset file name enables path traversal on file write",
                  "severity": "HIGH",
                  "cvss": 7.5,
                  "cwe": "CWE-22",
                  "description": "...",
                  "evidence": "this.$assetManager.open(this.$fileName); ... new FileOutputStream(this.$outFile);",
                  "poc_steps": "1. ...\\n2. ...\\n3. ...",
                  "remediation": "...",
                  "detection_regex": "..."
                }
              ]
            }
            """;

        Path dbPath = tmp.resolve("test.sqlite");
        Path rulesPath = tmp.resolve("learned_rules.json");
        try (SqliteStore store = new SqliteStore(dbPath.toString())) {
            store.insertFunctionDecompilations(List.of(new SqliteStore.DecompilationResult(
                    "invokeSuspend", "CopyUtil$Companion$copyFileFromAssets$1", sourceCode, "App")));
            LearnedRulesStore rs = new LearnedRulesStore(rulesPath);

            new LlmEnricher(new FakeProvider(llmJson), LlmMode.FIND_VULNS,
                    new MemoryCache(), false, PackagePlatform.ANDROID, rs)
                    .enrich(store, "App");

            var vulns = store.getVulnerabilities("App");
            assertEquals(1, vulns.size());
            assertTrue(vulns.get(0).get("rule_id").toString().endsWith("-ADHOC"),
                    "placeholder regex must not become a learned rule id");
            assertEquals("", String.valueOf(vulns.get(0).get("description")),
                    "ellipsis description should be stored as empty");
            assertEquals("", String.valueOf(vulns.get(0).get("remediation")));
            assertEquals("", String.valueOf(vulns.get(0).get("poc_steps")));
            assertFalse(String.valueOf(vulns.get(0).get("evidence")).isBlank());
            assertEquals(0, rs.size(), "placeholder regex must NOT be persisted");
        }
    }

    @Test void rejectsRegexThatFailsSelfTest(@TempDir Path tmp) throws Exception {
        // Function source contains 'window.postMessage' (offset 0-ish) then 'evaluateJavaScript' later
        String sourceCode =
            "void f() {\n" +
            "  pcVar3 = \"window.postMessage({token: null}, '*')\";\n" +
            "  _objc_msgSend(obj, PTR_s_evaluateJavaScript_xxx, pcVar3, 0);\n" +
            "}";

        // LLM returns a regex written for SOURCE order: evaluateJavaScript BEFORE window.postMessage
        // This regex will compile fine but won't match the decompiled (reversed) order.
        String llmJson = """
            {
              "vulnerabilities": [
                {
                  "scope": "XSS",
                  "title": "Bad regex",
                  "severity": "HIGH",
                  "cvss": 7.5,
                  "cwe": "CWE-79",
                  "description": "Regex assumes source order",
                  "evidence": "...",
                  "poc_steps": "1.",
                  "remediation": "fix",
                  "detection_regex": "evaluateJavaScript[^\\"]{0,80}\\"window\\\\.postMessage"
                }
              ]
            }
            """;

        Path dbPath = tmp.resolve("test.sqlite");
        Path rulesPath = tmp.resolve("learned_rules.json");
        try (SqliteStore store = new SqliteStore(dbPath.toString())) {
            store.insertFunctionDecompilations(List.of(new SqliteStore.DecompilationResult(
                    "f", "C", sourceCode, "App")));
            LearnedRulesStore rs = new LearnedRulesStore(rulesPath);

            new LlmEnricher(new FakeProvider(llmJson), LlmMode.FIND_VULNS,
                    new MemoryCache(), false, rs).enrich(store, "App");

            // Finding is still recorded as an ADHOC vulnerability
            var vulns = store.getVulnerabilities("App");
            assertEquals(1, vulns.size());
            assertTrue(vulns.get(0).get("rule_id").toString().endsWith("-ADHOC"),
                    "non-matching regex should produce ADHOC rule_id");

            // No rule persisted — would never fire anyway
            assertEquals(0, rs.size(), "regex that fails self-test must NOT be persisted");
        }
    }

    @Test void dedupesSameRegexAcrossScans(@TempDir Path tmp) throws Exception {
        Path dbPath = tmp.resolve("test.sqlite");
        Path rulesPath = tmp.resolve("learned_rules.json");

        try (SqliteStore store = new SqliteStore(dbPath.toString())) {
            // Use the same SAMPLE_JSON regexes, so the function code must match both
            String src =
                "  evaluateJavaScript s stringWithFormat %@ END\n" +
                "  SecItemAdd(query, NULL); END";
            store.insertFunctionDecompilations(List.of(new SqliteStore.DecompilationResult(
                    "f1", "C1", src, "App")));
            LearnedRulesStore rs = new LearnedRulesStore(rulesPath);

            // Run twice with the same JSON
            new LlmEnricher(new FakeProvider(SAMPLE_JSON), LlmMode.FIND_VULNS,
                    new MemoryCache(), false, rs).enrich(store, "App");
            new LlmEnricher(new FakeProvider(SAMPLE_JSON), LlmMode.FIND_VULNS,
                    new MemoryCache(), false, rs).enrich(store, "App");

            // Should NOT add duplicate rules
            assertEquals(2, rs.size(), "duplicate regex should not produce duplicate rules");
        }
    }

    private static final String SAMPLE_OFFENSIVE_JSON = """
        {
          "offensive_targets": [
            {
              "category": "SSL_PINNING",
              "title": "Bypass OkHttp CertificatePinner",
              "priority": "HIGH",
              "target_symbols": ["okhttp3.CertificatePinner.check"],
              "why_critical": "Blocks MITM with user CA",
              "bypass_strategy": "Hook check() and return early",
              "frida_script": "Java.perform(function() {\\n  var C = Java.use('okhttp3.CertificatePinner');\\n  C.check.overload('java.lang.String', 'java.util.List').implementation = function(a,b){ console.log('bypass '+a); };\\n});",
              "script_notes": "frida -U -f app -l pin.js",
              "mitm_notes": "Install Burp CA on device",
              "confidence": "HIGH",
              "evidence": "CertificatePinner.check(hostname, peerCertificates)"
            },
            {
              "category": "CRYPTO",
              "title": "...",
              "priority": "CRITICAL",
              "frida_script": "...",
              "confidence": "LOW"
            }
          ]
        }
        """;

    @Test void offensiveStoresCleanedJsonWithoutPromotingVulns(@TempDir Path tmp) throws Exception {
        Path dbPath = tmp.resolve("test.sqlite");
        Path rulesPath = tmp.resolve("learned_rules.json");
        try (SqliteStore store = new SqliteStore(dbPath.toString())) {
            store.insertFunctionDecompilations(List.of(new SqliteStore.DecompilationResult(
                    "check", "okhttp3.CertificatePinner",
                    "void check(String host, List peers) { this.pins.check(host); }",
                    "App", "JADX")));
            LearnedRulesStore rs = new LearnedRulesStore(rulesPath);

            new LlmEnricher(new FakeProvider(SAMPLE_OFFENSIVE_JSON), LlmMode.OFFENSIVE,
                    new MemoryCache(), false, PackagePlatform.ANDROID, rs)
                    .enrich(store, "App");

            assertEquals(0, store.getVulnerabilities("App").size(),
                    "OFFENSIVE must not promote into Vulnerabilities");
            assertEquals(0, rs.size(), "OFFENSIVE must not persist learned rules");

            var findings = store.getLlmFindings("App");
            assertEquals(1, findings.size());
            assertEquals("OFFENSIVE", findings.get(0).get("mode").toString());
            String text = findings.get(0).get("finding").toString();
            assertTrue(text.contains("offensive_targets"));
            assertTrue(text.contains("Bypass OkHttp CertificatePinner"));
            assertTrue(text.contains("\"phase\":\"TRANSPORT\"") || text.contains("\"phase\": \"TRANSPORT\""),
                    "SSL_PINNING should map to TRANSPORT phase: " + text);
            assertFalse(text.contains("\"title\":\"...\""), "placeholder title must be dropped");
        }
    }

    @Test void offensivePhaseMappingAndEnums() {
        assertEquals("ENVIRONMENT", LlmEnricher.normalizeOffensivePhase("", "ROOT_DETECTION"));
        assertEquals("ENVIRONMENT", LlmEnricher.normalizeOffensivePhase("", "JAILBREAK"));
        assertEquals("TRANSPORT", LlmEnricher.normalizeOffensivePhase("", "SSL_PINNING"));
        assertEquals("SECRETS", LlmEnricher.normalizeOffensivePhase("", "CRYPTO"));
        assertEquals("SESSION", LlmEnricher.normalizeOffensivePhase("", "BIOMETRIC"));
        assertEquals("SESSION", LlmEnricher.normalizeOffensivePhase("", "OTHER"));
        assertEquals("SECRETS", LlmEnricher.normalizeOffensivePhase("SECRETS", "SSL_PINNING"));
        assertEquals("HIGH", LlmEnricher.normalizeOffensivePriority("high"));
        assertEquals("MEDIUM", LlmEnricher.normalizeOffensivePriority("LOW"));
        assertEquals("LOW", LlmEnricher.normalizeOffensiveConfidence("low"));
        assertTrue(LlmEnricher.isHollowFridaScript("..."));
        assertTrue(LlmEnricher.isHollowFridaScript("// TODO implement"));
        assertFalse(LlmEnricher.isHollowFridaScript(
                "Java.perform(function(){ Java.use('x').y.implementation=function(){}; });"));
    }

    @Test void scannerPicksUpLearnedRules(@TempDir Path tmp) throws Exception {
        Path dbPath = tmp.resolve("test.sqlite");
        Path rulesPath = tmp.resolve("learned_rules.json");

        try (SqliteStore store = new SqliteStore(dbPath.toString())) {
            // Insert decompiled function containing the dangerous pattern
            // Order matches XSS regex: evaluateJavaScript before stringWithFormat before %@
            // First line satisfies the XSS regex (avoids ')' between tokens since [^)]).
            // Second line satisfies the KEYCHAIN regex which requires SecItemAdd(...) parens.
            String src =
                "  evaluateJavaScript x stringWithFormat %@ END\n" +
                "  SecItemAdd(query, NULL); END";
            store.insertFunctionDecompilations(List.of(new SqliteStore.DecompilationResult(
                    "sendToken", "WebViewController", src, "App")));

            LearnedRulesStore rs = new LearnedRulesStore(rulesPath);
            new LlmEnricher(new FakeProvider(SAMPLE_JSON), LlmMode.FIND_VULNS,
                    new MemoryCache(), false, rs).enrich(store, "App");
            int learnedCount = rs.size();
            assertTrue(learnedCount >= 1);

            // Wipe vulnerabilities and re-run scanner without LLM — learned rule must still fire
            store.clearVulnerabilities("App");

            int found = new VulnerabilityScanner().scan(store, "App", rs);
            assertTrue(found > 0, "learned rule should detect the same pattern");

            List<java.util.Map<String, Object>> vulns = store.getVulnerabilities("App");
            boolean hasLearned = vulns.stream().anyMatch(v -> v.get("rule_id").toString().startsWith("LLM-"));
            assertTrue(hasLearned, "expected a rule with LLM- prefix to fire");
        }
    }
}
