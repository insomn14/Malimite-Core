package io.mailmite.core;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for recovering {@code {"vulnerabilities":[...]}} from messy LLM responses.
 */
class LlmEnricherExtractTest {

    private static final String ONE_VULN = """
        {
          "vulnerabilities": [
            {
              "scope": "AUTH",
              "title": "Client-side login flag in NSUserDefaults",
              "severity": "HIGH",
              "cvss": 7.5,
              "cwe": "CWE-287",
              "description": "Auth gated on NSUserDefaults bool userLoggedIn",
              "evidence": "boolForKey userLoggedIn",
              "poc_steps": "1. set userLoggedIn=YES\\n2. launch app",
              "remediation": "Validate server session / keychain token",
              "detection_regex": "(?:userLoggedIn[\\\\s\\\\S]{0,2000}boolForKey|boolForKey[\\\\s\\\\S]{0,2000}userLoggedIn)"
            }
          ]
        }
        """;

    @Test void extractsCleanJson() {
        JsonObject o = LlmEnricher.extractVulnsJson(ONE_VULN);
        assertNotNull(o);
        assertEquals(1, o.getAsJsonArray("vulnerabilities").size());
    }

    @Test void extractsEmptyArray() {
        JsonObject o = LlmEnricher.extractVulnsJson("{\"vulnerabilities\": []}");
        assertNotNull(o);
        assertEquals(0, o.getAsJsonArray("vulnerabilities").size());
    }

    @Test void extractsFencedJson() {
        String raw = "```json\n" + ONE_VULN.trim() + "\n```";
        JsonObject o = LlmEnricher.extractVulnsJson(raw);
        assertNotNull(o);
        assertEquals(1, o.getAsJsonArray("vulnerabilities").size());
        assertEquals("AUTH", o.getAsJsonArray("vulnerabilities").get(0).getAsJsonObject()
                .get("scope").getAsString());
    }

    @Test void extractsFencedJsonWithProseAroundFence() {
        String raw = "Here is my analysis.\n```json\n" + ONE_VULN.trim() + "\n```\nDone.";
        JsonObject o = LlmEnricher.extractVulnsJson(raw);
        assertNotNull(o);
        assertEquals(1, o.getAsJsonArray("vulnerabilities").size());
    }

    @Test void extractsJsonEmbeddedAfterProse() {
        String raw = """
            We need answer JSON. Severity maybe HIGH/CRITICAL depending.
            Auth bypass via NSUserDefaults userLoggedIn looks real. Crafting JSON now.

            """ + ONE_VULN.trim();
        JsonObject o = LlmEnricher.extractVulnsJson(raw);
        assertNotNull(o, "prose + trailing JSON must be recoverable");
        JsonArray arr = o.getAsJsonArray("vulnerabilities");
        assertEquals(1, arr.size());
        assertEquals("HIGH", arr.get(0).getAsJsonObject().get("severity").getAsString());
    }

    @Test void repairsTruncatedJsonKeepingCompleteEntries() {
        // Complete first vuln, truncated mid-second object
        String truncated = """
            Some preamble before the JSON object.
            {
              "vulnerabilities": [
                {
                  "scope": "AUTH",
                  "title": "Client-side login flag",
                  "severity": "HIGH",
                  "cvss": 7.5,
                  "cwe": "CWE-287",
                  "description": "NSUserDefaults auth bypass",
                  "evidence": "userLoggedIn",
                  "poc_steps": "1. set flag",
                  "remediation": "use keychain",
                  "detection_regex": "userLoggedIn"
                },
                {
                  "scope": "NETWORK",
                  "title": "Incomplete
            """.trim();
        JsonObject o = LlmEnricher.extractVulnsJson(truncated);
        assertNotNull(o, "truncated JSON with one complete entry should repair");
        assertEquals(1, o.getAsJsonArray("vulnerabilities").size());
        assertEquals("AUTH", o.getAsJsonArray("vulnerabilities").get(0).getAsJsonObject()
                .get("scope").getAsString());
    }

    @Test void returnsNullForProseOnlyWithoutJson() {
        String prose = """
            We need answer JSON. Function LoginController viewDidLoad reads NSUserDefaults
            boolForKey userLoggedIn. Severity maybe HIGH/CRITICAL depending. Auth bypass.
            Need craft detection_regex. Never got around to emitting the object.
            """;
        assertNull(LlmEnricher.extractVulnsJson(prose));
    }

    @Test void returnsNullForBlank() {
        assertNull(LlmEnricher.extractVulnsJson(null));
        assertNull(LlmEnricher.extractVulnsJson("   "));
    }

    @Test void promotesEmbeddedJsonIntoVulnerabilitiesTable(@TempDir Path tmp) throws Exception {
        String messy = """
            Thinking out loud about AUTH bypass CRITICAL vs HIGH...
            Final answer:
            """ + ONE_VULN.trim();

        Path dbPath = tmp.resolve("test.sqlite");
        Path rulesPath = tmp.resolve("learned_rules.json");
        try (SqliteStore store = new SqliteStore(dbPath.toString())) {
            String src =
                "  Swift::String::init(\"userLoggedIn\",0xc,1);\n" +
                "  _objc_msgSend(puVar1, PTR_s_boolForKey__10002d2e8, pNVar2);\n";
            store.insertFunctionDecompilations(List.of(new SqliteStore.DecompilationResult(
                    "viewDidLoad", "LoginController", src, "App")));

            LearnedRulesStore rs = new LearnedRulesStore(rulesPath);
            new LlmEnricher(new FakeProvider(messy), LlmMode.FIND_VULNS,
                    new MemoryCache(), false, rs).enrich(store, "App");

            var vulns = store.getVulnerabilities("App");
            assertEquals(1, vulns.size(), "embedded JSON must promote to Vulnerabilities");
            assertTrue(vulns.get(0).get("rule_id").toString().startsWith("LLM-AUTH-"),
                    "expected LLM-AUTH-* rule id, got " + vulns.get(0).get("rule_id"));
            assertEquals("HIGH", vulns.get(0).get("severity").toString());
        }
    }

    @Test void promotesFencedJsonIntoVulnerabilitiesTable(@TempDir Path tmp) throws Exception {
        String fenced = "```json\n" + ONE_VULN.trim() + "\n```";
        Path dbPath = tmp.resolve("test.sqlite");
        try (SqliteStore store = new SqliteStore(dbPath.toString())) {
            String src =
                "  userLoggedIn\n  boolForKey\n";
            store.insertFunctionDecompilations(List.of(new SqliteStore.DecompilationResult(
                    "viewDidLoad", "LoginController", src, "App")));

            new LlmEnricher(new FakeProvider(fenced), LlmMode.FIND_VULNS,
                    new MemoryCache(), false, new LearnedRulesStore(tmp.resolve("rules.json")))
                    .enrich(store, "App");

            var vulns = store.getVulnerabilities("App");
            assertEquals(1, vulns.size());
            assertTrue(vulns.get(0).get("rule_id").toString().startsWith("LLM-"));
        }
    }

    static class FakeProvider implements LlmProvider {
        private final String response;
        FakeProvider(String response) { this.response = response; }
        @Override public String complete(String systemPrompt, String userMessage) { return response; }
    }

    static class MemoryCache implements LlmCache {
        @Override public Optional<String> get(String hash) { return Optional.empty(); }
        @Override public void put(String hash, String value) { /* no-op */ }
    }
}
