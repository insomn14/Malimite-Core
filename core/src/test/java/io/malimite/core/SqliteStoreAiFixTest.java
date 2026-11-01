package io.malimite.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies the AI Fix override columns: {@link SqliteStore#updateVulnerabilityAiFix} writes
 * reversible overrides without touching the original finding text, {@link SqliteStore#getVulnerabilities}
 * surfaces them, and {@link SqliteStore#revertVulnerabilityAiFix} restores the original values while
 * respecting a human's own manual triage override on severity/CVSS.
 */
class SqliteStoreAiFixTest {

    private static Vulnerability sample(String ruleId) {
        return new Vulnerability(
                ruleId, "Hardcoded API key", "STORAGE", "CRITICAL", 9.1, "CWE-798",
                "Original terse description", "STRING", "0x1234", "api_key=abcdef",
                "0x1234 (__TEXT)", "1. find it", "Use Keychain", "https://example.com/mstg");
    }

    @Test
    void appliesAiFixAsOverridesWithoutTouchingOriginals(@TempDir Path tmp) throws Exception {
        try (SqliteStore store = new SqliteStore(tmp.resolve("aifix1.sqlite").toString())) {
            store.insertVulnerability(sample("MSTG-STORAGE-1"), "App");
            long id = (long) store.getVulnerabilities("App").get(0).get("id");

            boolean ok = store.updateVulnerabilityAiFix("App", id,
                    "AI-rewritten description", "AI-rewritten evidence",
                    "1. AI step one\n2. AI step two", "AI-rewritten remediation",
                    "HIGH", 7.8, "deepseek", "deepseek-v4-flash");
            assertTrue(ok, "update should affect one row");

            Map<String, Object> row = store.getVulnerabilities("App").get(0);
            // Originals are untouched
            assertEquals("Original terse description", row.get("description"));
            assertEquals("api_key=abcdef", row.get("evidence"));
            assertEquals("1. find it", row.get("poc_steps"));
            assertEquals("Use Keychain", row.get("remediation"));
            assertEquals("CRITICAL", row.get("severity"));
            assertEquals(9.1, (double) row.get("cvss_score"), 0.0001);
            // Overrides are populated
            assertEquals("AI-rewritten description", row.get("override_description"));
            assertEquals("AI-rewritten evidence", row.get("override_evidence"));
            assertEquals("1. AI step one\n2. AI step two", row.get("override_poc_steps"));
            assertEquals("AI-rewritten remediation", row.get("override_remediation"));
            assertEquals("HIGH", row.get("override_severity"));
            assertEquals(7.8, (double) row.get("override_cvss_score"), 0.0001);
            assertEquals("applied", row.get("ai_fix_status"));
            assertEquals("deepseek", row.get("ai_fix_provider"));
            assertEquals("deepseek-v4-flash", row.get("ai_fix_model"));
            assertNotNull(row.get("ai_fix_at"));
        }
    }

    @Test
    void revertClearsOverridesAndRestoresAiOwnedSeverity(@TempDir Path tmp) throws Exception {
        try (SqliteStore store = new SqliteStore(tmp.resolve("aifix2.sqlite").toString())) {
            store.insertVulnerability(sample("MSTG-STORAGE-1"), "App");
            long id = (long) store.getVulnerabilities("App").get(0).get("id");

            store.updateVulnerabilityAiFix("App", id,
                    "AI description", "AI evidence", "AI poc", "AI remediation",
                    "LOW", 3.0, "openai", "gpt-4o-mini");

            boolean reverted = store.revertVulnerabilityAiFix("App", id);
            assertTrue(reverted);

            Map<String, Object> row = store.getVulnerabilities("App").get(0);
            assertNull(row.get("override_description"));
            assertNull(row.get("override_evidence"));
            assertNull(row.get("override_poc_steps"));
            assertNull(row.get("override_remediation"));
            // AI owned the severity override (no prior manual triage) -> cleared on revert
            assertNull(row.get("override_severity"));
            assertNull(row.get("override_cvss_score"));
            assertEquals("reverted", row.get("ai_fix_status"));
            // Original fields remain exactly as scanned
            assertEquals("Original terse description", row.get("description"));
            assertEquals("CRITICAL", row.get("severity"));
        }
    }

    @Test
    void revertDoesNotClobberAPreexistingManualTriageOverride(@TempDir Path tmp) throws Exception {
        try (SqliteStore store = new SqliteStore(tmp.resolve("aifix3.sqlite").toString())) {
            store.insertVulnerability(sample("MSTG-STORAGE-1"), "App");
            long id = (long) store.getVulnerabilities("App").get(0).get("id");

            // Human triages first: downgrades to LOW with a reviewer note.
            store.updateVulnerabilityTriage(id, "accepted_risk", "LOW", 2.0, "Server-side key only");

            // AI Fix only rewrites text fields (severity args null -> does not touch risk).
            store.updateVulnerabilityAiFix("App", id,
                    "AI description", "AI evidence", "AI poc", "AI remediation",
                    null, null, "ollama", "llama3.1");

            Map<String, Object> mid = store.getVulnerabilities("App").get(0);
            assertEquals("LOW", mid.get("override_severity"), "manual triage severity preserved through AI fix");
            assertEquals(2.0, (double) mid.get("override_cvss_score"), 0.0001);

            boolean reverted = store.revertVulnerabilityAiFix("App", id);
            assertTrue(reverted);

            Map<String, Object> row = store.getVulnerabilities("App").get(0);
            assertNull(row.get("override_description"), "AI Fix text override cleared");
            // Human's manual triage severity/CVSS survives the AI Fix revert
            assertEquals("LOW", row.get("override_severity"));
            assertEquals(2.0, (double) row.get("override_cvss_score"), 0.0001);
            assertEquals("accepted_risk", row.get("status"), "manual status untouched by AI fix/revert");
        }
    }

    @Test
    void getVulnerabilityReturnsSingleRowById(@TempDir Path tmp) throws Exception {
        try (SqliteStore store = new SqliteStore(tmp.resolve("aifix4.sqlite").toString())) {
            store.insertVulnerability(sample("MSTG-STORAGE-1"), "App");
            store.insertVulnerability(sample("MSTG-NETWORK-2"), "App");
            List<Map<String, Object>> all = store.getVulnerabilities("App");
            long firstId = (long) all.get(0).get("id");

            Map<String, Object> row = store.getVulnerability("App", firstId);
            assertNotNull(row);
            assertEquals(firstId, row.get("id"));

            assertNull(store.getVulnerability("App", -999L), "unknown id returns null");
        }
    }
}
