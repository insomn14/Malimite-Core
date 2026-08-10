package io.mailmite.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Covers the two dedup-related guarantees that were tightened in v0.1.x:
 *   1. Regex normalisation — whitespace and {@code [\s\S]/[\S\s]} differences
 *      do not produce duplicate rules.
 *   2. Cross-process safety — a rule written to disk by another process
 *      between this store's construction and {@code addRule()} is picked up
 *      (via the reload-under-lock pattern) and dedup applies.
 */
class LearnedRulesStoreTest {

    // ── regex normalization ───────────────────────────────────────────────────

    @Test void normalizesWhitespaceOutsideCharClass() {
        assertEquals(
                LearnedRulesStore.normalizeRegex("evaluateJavaScript[\\s\\S]{0,500}stringWithFormat"),
                LearnedRulesStore.normalizeRegex("evaluateJavaScript [\\s\\S] {0,500} stringWithFormat"),
                "whitespace outside [...] should be ignored for dedup");
    }

    @Test void preservesWhitespaceInsideCharClass() {
        // A literal space inside [...] really matches a space — must NOT be stripped.
        String a = LearnedRulesStore.normalizeRegex("foo[ ]bar");
        String b = LearnedRulesStore.normalizeRegex("foo[]bar");
        assertNotEquals(a, b, "whitespace inside character classes is significant");
    }

    @Test void canonicalisesSlashSSlashSOrdering() {
        assertEquals(
                LearnedRulesStore.normalizeRegex("a[\\s\\S]+b"),
                LearnedRulesStore.normalizeRegex("a[\\S\\s]+b"));
    }

    @Test void emptyAndNullSafe() {
        assertEquals("", LearnedRulesStore.normalizeRegex(null));
        assertEquals("", LearnedRulesStore.normalizeRegex(""));
    }

    @Test void escapeSequencesPreserved() {
        // \s is an escape that means "whitespace" — its own backslash should pass through
        String n = LearnedRulesStore.normalizeRegex("a\\sb");
        assertTrue(n.contains("\\s"), "escape sequence \\s must survive normalization");
    }

    // ── addRule dedup using normalized regex ──────────────────────────────────

    @Test void dedupsRegexThatDiffersOnlyByWhitespace(@TempDir Path tmp) {
        Path file = tmp.resolve("learned.json");
        LearnedRulesStore store = new LearnedRulesStore(file);

        String id1 = store.addRule("XSS", "JS injection", "CODE", "HIGH", 7.5, "CWE-79",
                "desc", "fix", "DECOMPILED",
                "evaluateJavaScript[\\s\\S]{0,500}stringWithFormat",
                "poc", "ref");
        assertNotNull(id1);

        String id2 = store.addRule("XSS", "JS injection variant", "CODE", "HIGH", 7.5, "CWE-79",
                "desc", "fix", "DECOMPILED",
                "evaluateJavaScript [\\s\\S] {0,500} stringWithFormat",   // cosmetically different
                "poc", "ref");
        assertEquals(id1, id2, "near-duplicate regex must reuse the existing rule ID");
        assertEquals(1, store.size(), "store should contain exactly one rule");
    }

    @Test void distinctScopesNeverCollideEvenWithSameRegex(@TempDir Path tmp) {
        Path file = tmp.resolve("learned.json");
        LearnedRulesStore store = new LearnedRulesStore(file);

        String id1 = store.addRule("XSS", "t", "CODE", "HIGH", 7.5, "CWE-79",
                "d", "r", "DECOMPILED", "shared_pattern", "p", "u");
        String id2 = store.addRule("INJECTION", "t", "CODE", "HIGH", 7.5, "CWE-89",
                "d", "r", "DECOMPILED", "shared_pattern", "p", "u");
        assertNotEquals(id1, id2, "same regex under different scopes should be kept distinct");
        assertEquals(2, store.size());
    }

    // ── cross-process safety: reload-under-lock ───────────────────────────────

    @Test void pickUpRuleWrittenByAnotherProcessBetweenConstructorAndAdd(@TempDir Path tmp) throws Exception {
        Path file = tmp.resolve("learned.json");

        // Store A is constructed first and loads an empty file
        LearnedRulesStore a = new LearnedRulesStore(file);
        assertEquals(0, a.size());

        // Simulate "another process" by writing rules out-of-band, while A is still alive
        LearnedRulesStore b = new LearnedRulesStore(file);
        String idFromB = b.addRule("XSS", "by-B", "CODE", "HIGH", 7.5, "CWE-79",
                "d", "r", "DECOMPILED", "B_regex", "p", "u");
        assertNotNull(idFromB);
        assertTrue(Files.exists(file));

        // Now A tries to add a rule. The implementation MUST reload from disk
        // inside the lock and notice B's rule, so A's id sequence continues
        // from there instead of clobbering it.
        String idFromA = a.addRule("XSS", "by-A", "CODE", "HIGH", 7.5, "CWE-79",
                "d", "r", "DECOMPILED", "A_regex", "p", "u");
        assertNotNull(idFromA);
        assertNotEquals(idFromB, idFromA, "A's new ID must not collide with B's pre-existing one");

        // Both rules must be persisted — no lost write
        LearnedRulesStore fresh = new LearnedRulesStore(file);
        assertEquals(2, fresh.size(), "both rules must survive after reload");
    }

    @Test void dedupAlsoAppliesAgainstReloadedRules(@TempDir Path tmp) {
        Path file = tmp.resolve("learned.json");

        LearnedRulesStore a = new LearnedRulesStore(file);
        LearnedRulesStore b = new LearnedRulesStore(file);

        String idB = b.addRule("XSS", "JS inj", "CODE", "HIGH", 7.5, "CWE-79",
                "d", "r", "DECOMPILED",
                "evaluateJavaScript[\\s\\S]{0,500}stringWithFormat",
                "p", "u");

        // A tries to add the same vulnerability with whitespace variation;
        // since A reloads under lock, it should see B's rule and dedup against it.
        String idA = a.addRule("XSS", "JS inj alt", "CODE", "HIGH", 7.5, "CWE-79",
                "d", "r", "DECOMPILED",
                "evaluateJavaScript [\\s\\S] {0,500} stringWithFormat",
                "p", "u");

        assertEquals(idB, idA, "A must reuse B's rule after reload + normalisation dedup");
    }

    @Test void rejectsInvalidRegexBeforeTakingLock(@TempDir Path tmp) {
        Path file = tmp.resolve("learned.json");
        LearnedRulesStore store = new LearnedRulesStore(file);
        String id = store.addRule("XSS", "t", "CODE", "HIGH", 7.5, "CWE-79",
                "d", "r", "DECOMPILED", "[unclosed", "p", "u");
        assertNull(id, "malformed regex should return null without persisting anything");
        assertEquals(0, store.size());
        assertFalse(Files.exists(file), "no JSON file should be written when nothing was added");
    }

    @Test void rejectsPlaceholderEllipsisRegex(@TempDir Path tmp) {
        Path file = tmp.resolve("learned.json");
        LearnedRulesStore store = new LearnedRulesStore(file);
        assertNull(store.addRule("PATH-TRAVERSAL", "t", "CODE", "HIGH", 7.5, "CWE-22",
                "d", "r", "DECOMPILED", "...", "p", "u"));
        assertNull(store.addRule("PATH-TRAVERSAL", "t", "CODE", "HIGH", 7.5, "CWE-22",
                "d", "r", "DECOMPILED", ".*", "p", "u"));
        assertEquals(0, store.size());
        assertTrue(LearnedRulesStore.isPlaceholderText("..."));
        assertTrue(LearnedRulesStore.isPlaceholderText("1. ...\n2. ...\n3. ..."));
        assertFalse(LearnedRulesStore.isUsableDetectionRegex("..."));
        assertTrue(LearnedRulesStore.isUsableDetectionRegex(
                "new File\\(\\s*CopyUtil\\.DOWNLOADS_DIRECTORY\\s*,\\s*fileName\\s*\\)"));
    }

    @Test void asVulnerabilityRulesSkipsStoredPlaceholderRegex(@TempDir Path tmp) throws Exception {
        Path file = tmp.resolve("learned.json");
        Files.writeString(file, """
            {"rules":[{
              "id":"LLM-PATH-TRAVERSAL-001",
              "scope":"PATH-TRAVERSAL",
              "title":"Bad",
              "category":"CODE",
              "severity":"HIGH",
              "cvssScore":7.5,
              "cwe":"CWE-22",
              "description":"...",
              "remediation":"...",
              "referenceUrl":"ref",
              "target":"DECOMPILED",
              "regex":"...",
              "pocTemplate":"1. ...",
              "createdAt":1,
              "platform":"ANDROID"
            }]}
            """);
        LearnedRulesStore store = new LearnedRulesStore(file, PackagePlatform.ANDROID);
        assertEquals(1, store.size(), "raw store still holds the bad rule");
        assertEquals(0, store.asVulnerabilityRules().size(), "scanner must not load placeholder regex");
    }
}
