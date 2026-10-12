package io.malimite.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The regexes below are real rules that produced false positives on real apps (an iOS crackme and three APKs)
 * before the quality gates existed.
 */
class RuleQualityTest {

    @Test
    void decompilerVocabularyAloneIsNotAnAnchor() {
        String[] noise = {
                "\\*\\w+\\s*=\\s*\\*\\w+\\s*\\^\\s*\\w+;",                       // "XOR cipher": 14 hits, all VM opcode handlers
                "SoftwareBreakpoint\\s*\\(",                                    // how Ghidra prints a compiler trap
                "\\*\\(uint \\*\\)\\(param_\\d+ \\+ 0x[0-9a-f]+\\)",           // any struct field access
                "\\(char\\)\\w+\\[[0-9]+\\]|\\*\\(ulong \\*\\)\\(\\w+ \\+ [0-9]+\\)",
                "unaff_\\w+\\s*\\+\\s*\\*\\(int\\s*\\*\\)\\(param_\\d+\\.\\w+\\s*\\+\\s*0x[0-9a-fA-F]+\\)",
                "\\} while\\s*\\(\\s*_\\w+\\s*==\\s*_\\w+\\s*\\)",
                "objc_msgSend|objc_retain|objc_release",                         // present in practically every function
        };
        for (String re : noise) assertFalse(RuleQuality.hasSemanticAnchor(re), re);
    }

    @Test
    void everyAlternativeNeedsItsOwnAnchor() {
        assertTrue(RuleQuality.hasSemanticAnchor("SecItemAdd\\(|SecItemUpdate\\("));
        assertFalse(RuleQuality.hasSemanticAnchor("SecItemAdd\\(|\\*\\w+ = \\*\\w+ \\^ \\w+;"),
                "one specific branch must not excuse a generic one");
    }

    @Test
    void specificApiNamesPass() {
        String[] good = {
                "CCCrypt\\s*\\(", "NSUserDefaults[\\s\\S]{0,200}password", "kSecAttrAccessibleAlways",
                "Cipher\\.getInstance\\(\"DES", "Runtime\\.getRuntime\\(\\)\\.exec\\(", "openConnection\\(\\)[\\s\\S]{0,300}HttpURLConnection",
                "Base64\\.encodeToString\\(bytes,\\s*0\\)", "(?i)password\\s*=\\s*\"[^\"]+\"",
        };
        for (String re : good) assertTrue(RuleQuality.passes(re), re);
    }

    @Test
    void shortUnboundedWordsAreRejectedBecauseTheyMatchInsideLongerIdentifiers() {
        // real rule: "Command Injection via JavaScript Interface", CRITICAL. Matched execute(), Executors and
        // RuntimeIntegritySdk: 499 / 543 / 166 functions in three apps.
        String re = "(?:Runtime|exec)[\\s\\S]{0,200}(?:exec|Runtime)";
        assertTrue(RuleQuality.hasSemanticAnchor(re), "it does contain words, so the anchor gate alone passes it");
        assertFalse(RuleQuality.isBounded(re));
        assertFalse(RuleQuality.passes(re));
        assertTrue(Pattern.compile(re).matcher("response = call.execute(); executor.execute(task);").find(),
                "documents why: it matches ordinary OkHttp/executor code");
        // the delimited form of the same idea is fine
        assertTrue(RuleQuality.passes("Runtime\\.getRuntime\\(\\)\\.exec\\([\\s\\S]{0,500}\"-c\""));
        // a long camelCase literal is distinctive even without delimiters
        assertTrue(RuleQuality.passes("addJavascriptInterface"));
        assertFalse(RuleQuality.passes("exec"));
        assertFalse(RuleQuality.passes("DES"));       // would match DESCRIPTION
        assertTrue(RuleQuality.passes("\"DES\""));    // quoted: delimited
    }

    @Test
    void groupSyntaxIsNotMistakenForADelimiter() {
        for (String re : new String[] {"(?:Runtime|exec)", "(?i:Runtime|exec)", "(?<name>Runtime|exec)", "(?=exec)"})
            assertFalse(RuleQuality.isBounded(re), re);
        assertTrue(RuleQuality.isBounded("(?:Runtime)\\.exec\\("));
    }

    @Test
    void alternationIsSplitOnlyAtTheTopLevel() {
        assertEquals(List.of("a(?:b|c)d", "e"), RuleQuality.topLevelAlternatives("a(?:b|c)d|e"));
        assertEquals(List.of("[|]x", "y"), RuleQuality.topLevelAlternatives("[|]x|y"));
        assertEquals(List.of("a\\|b"), RuleQuality.topLevelAlternatives("a\\|b"));
    }

    @Test
    void aPatternThatMatchesManyOtherFunctionsIsTooBroad() {
        List<String> corpus = new ArrayList<>();
        for (int i = 0; i < 156; i++) corpus.add(i % 11 == 0 ? "x = *p ^ q;" : "return " + i + ";");   // 15 of 156
        Pattern xor = Pattern.compile("\\*\\w+\\s*\\^\\s*\\w+;");
        assertEquals(5, RuleQuality.allowedHits(156));
        assertTrue(RuleQuality.isTooBroad(xor, "x = *p ^ q;", corpus));
        assertFalse(RuleQuality.isTooBroad(Pattern.compile("return 7;"), "return 7;", corpus));
        assertEquals(3, RuleQuality.allowedHits(10), "tiny apps still tolerate a few hits");
        assertEquals(30, RuleQuality.allowedHits(1000));
    }

    @Test
    void identicalCopiesOfTheSourceCountAsOtherFunctions() {
        List<String> corpus = new ArrayList<>();
        for (int i = 0; i < 20; i++) corpus.add("SecItemAdd(x);");       // the same helper duplicated 20 times
        assertTrue(RuleQuality.isTooBroad(Pattern.compile("SecItemAdd"), "SecItemAdd(x);", corpus));
    }

    @Test
    void ownSourceDoesNotCountAgainstTheRule() {
        List<String> corpus = List.of("only here: SecItemAdd(", "other");
        assertFalse(RuleQuality.isTooBroad(Pattern.compile("SecItemAdd"), "only here: SecItemAdd(", corpus));
    }

    @Test
    void learnedSeverityIsCappedButNeverRaised() {
        assertEquals("MEDIUM", RuleQuality.capSeverity("CRITICAL", "MEDIUM"));
        assertEquals("MEDIUM", RuleQuality.capSeverity("high", "MEDIUM"));
        assertEquals("MEDIUM", RuleQuality.capSeverity("MEDIUM", "MEDIUM"));
        assertEquals("LOW", RuleQuality.capSeverity("LOW", "MEDIUM"));
        assertEquals("INFO", RuleQuality.capSeverity("INFO", "MEDIUM"));
        assertEquals("MEDIUM", RuleQuality.capSeverity("bogus", "MEDIUM"));
        assertEquals(6.9, RuleQuality.capCvss(9.8, "MEDIUM"), 1e-9);
        assertEquals(5.3, RuleQuality.capCvss(5.3, "MEDIUM"), 1e-9);
        assertEquals("MEDIUM", RuleQuality.learnedMaxSeverity());   // default (MALIMITE_LEARNED_MAX_SEVERITY unset in tests)
    }

    @Test
    void storeRefusesToLearnGenericRulesAndIgnoresStoredOnes(@TempDir Path tmp) throws Exception {
        LearnedRulesStore store = new LearnedRulesStore(tmp.resolve("l.json"), PackagePlatform.IOS);
        assertNull(store.addRule("CRYPTO", "XOR", "CRYPTO", "MEDIUM", 5.0, "CWE-327", "d", "r", "DECOMPILED",
                "\\*\\w+\\s*=\\s*\\*\\w+\\s*\\^\\s*\\w+;", "p", "u"));
        assertEquals(0, store.size());

        // a store file written by an older version already contains one: it must not be loaded
        Files.writeString(tmp.resolve("old.json"), """
                {"rules":[
                 {"id":"LLM-CRYPTO-019","scope":"CRYPTO","title":"Simple XOR cipher","category":"CRYPTO","severity":"HIGH",
                  "cvssScore":7.4,"cwe":"CWE-327","description":"d","remediation":"r","referenceUrl":"u","target":"DECOMPILED",
                  "regex":"\\\\*\\\\w+\\\\s*=\\\\s*\\\\*\\\\w+\\\\s*\\\\^\\\\s*\\\\w+;","pocTemplate":"p","platform":"IOS"},
                 {"id":"LLM-OK-001","scope":"CRYPTO","title":"CCCrypt ECB","category":"CRYPTO","severity":"CRITICAL",
                  "cvssScore":9.1,"cwe":"CWE-327","description":"d","remediation":"r","referenceUrl":"u","target":"DECOMPILED",
                  "regex":"kCCOptionECBMode","pocTemplate":"p","platform":"IOS"}]}""");
        var rules = new LearnedRulesStore(tmp.resolve("old.json"), PackagePlatform.IOS).asVulnerabilityRules();
        assertEquals(1, rules.size());
        assertEquals("LLM-OK-001", rules.get(0).id());
        assertEquals("MEDIUM", rules.get(0).severity(), "an LLM-written rule is a lead, not a CRITICAL fact");
        assertEquals(6.9, rules.get(0).cvssScore(), 1e-9);
    }

    @Test
    void learnedRuleThatMatchesDozensOfFunctionsReportsNothing(@TempDir Path tmp) throws Exception {
        try (SqliteStore store = new SqliteStore(tmp.resolve("s.sqlite").toString())) {
            List<SqliteStore.DecompilationResult> fns = new ArrayList<>();
            for (int i = 0; i < 40; i++) fns.add(new SqliteStore.DecompilationResult("f" + i, "C", "call kSecAttrAccessibleAlways;", "app"));
            store.insertFunctionDecompilations(fns);
            LearnedRulesStore learned = new LearnedRulesStore(tmp.resolve("l.json"), PackagePlatform.IOS);
            assertNotNull(learned.addRule("STORAGE", "t", "STORAGE", "HIGH", 7.0, "CWE-922", "d", "r", "DECOMPILED",
                    "kSecAttrAccessibleAlways", "p", "u"));
            new VulnerabilityScanner().scan(store, "app", PackagePlatform.IOS, learned);
            assertEquals(0, store.getVulnerabilities("app").stream().filter(v -> String.valueOf(v.get("rule_id")).startsWith("LLM-")).count());
        }
    }

    @Test
    void learnedRuleWithFewHitsIsReportedWithCappedSeverity(@TempDir Path tmp) throws Exception {
        try (SqliteStore store = new SqliteStore(tmp.resolve("s.sqlite").toString())) {
            List<SqliteStore.DecompilationResult> fns = new ArrayList<>();
            for (int i = 0; i < 40; i++) fns.add(new SqliteStore.DecompilationResult("f" + i, "C",
                    i < 3 ? "call kSecAttrAccessibleAlways;" : "nothing", "app"));
            store.insertFunctionDecompilations(fns);
            LearnedRulesStore learned = new LearnedRulesStore(tmp.resolve("l.json"), PackagePlatform.IOS);
            learned.addRule("STORAGE", "t", "STORAGE", "CRITICAL", 9.1, "CWE-922", "d", "r", "DECOMPILED",
                    "kSecAttrAccessibleAlways", "p", "u");
            new VulnerabilityScanner().scan(store, "app", PackagePlatform.IOS, learned);
            var hits = store.getVulnerabilities("app").stream().filter(v -> String.valueOf(v.get("rule_id")).startsWith("LLM-")).toList();
            assertEquals(3, hits.size());
            assertTrue(hits.stream().allMatch(v -> "MEDIUM".equals(v.get("severity"))), hits.toString());
        }
    }

    @Test
    void shippedSeedRulesAllPassTheGates() throws Exception {
        for (String name : new String[] {"learned_rules_ios.json", "learned_rules_android.json"}) {
            Path p = Path.of("..", "deploy", "rules", name);       // surefire runs in core/
            if (!Files.isRegularFile(p)) continue;                 // building from a source archive without deploy/
            var root = com.google.gson.JsonParser.parseString(Files.readString(p)).getAsJsonObject();
            List<String> bad = new ArrayList<>();
            for (var el : root.getAsJsonArray("rules")) {
                var r = el.getAsJsonObject();
                String why = RuleQuality.rejection(r.get("regex").getAsString());
                if (why != null) bad.add(r.get("id").getAsString() + " (" + why + ")");
            }
            assertTrue(bad.isEmpty(), name + " ships rules the scanner would refuse to load: " + bad);
        }
    }

    // ── absence rules only apply when the feature they protect is in use ─────────────────────────────────────────

    private static boolean reported(String ruleId, PackagePlatform platform, Path db, List<String> codeBodies,
                                    List<String> strings) throws Exception {
        try (SqliteStore store = new SqliteStore(db.toString())) {
            List<SqliteStore.DecompilationResult> fns = new ArrayList<>();
            for (int i = 0; i < codeBodies.size(); i++)
                fns.add(new SqliteStore.DecompilationResult("f" + i, "C", codeBodies.get(i), "app"));
            store.insertFunctionDecompilations(fns);
            int i = 0;
            for (String v : strings) store.insertMachoString("a" + i++, v, "__cstring", "l", "app");
            new VulnerabilityScanner().scan(store, "app", platform,
                    new LearnedRulesStore(db.resolveSibling("none.json"), platform));
            return store.getVulnerabilities("app").stream().anyMatch(v -> ruleId.equals(v.get("rule_id")));
        }
    }

    @Test
    void pinningIsNotReportedForAnAppWithoutNetworking(@TempDir Path tmp) throws Exception {
        List<String> offline = List.of("[x setText:@\"hello\"];");
        assertFalse(reported("MSTG-NETWORK-4", PackagePlatform.IOS, tmp.resolve("a.sqlite"), offline, List.of("Congratulations")));
        assertFalse(reported("MASTG-TEST-0385", PackagePlatform.IOS, tmp.resolve("b.sqlite"), offline, List.of()));
    }

    @Test
    void thePlistDoctypeUrlDoesNotCountAsNetworking(@TempDir Path tmp) throws Exception {
        // every Info.plist starts with <!DOCTYPE plist ... "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        try (SqliteStore store = new SqliteStore(tmp.resolve("a.sqlite").toString())) {
            store.insertResourceString("Info.plist",
                    "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">", "plist");
            store.insertFunctionDecompilations(List.of(new SqliteStore.DecompilationResult("f", "C", "return;", "app")));
            new VulnerabilityScanner().scan(store, "app", PackagePlatform.IOS,
                    new LearnedRulesStore(tmp.resolve("none.json"), PackagePlatform.IOS));
            assertTrue(store.getVulnerabilities("app").stream()
                    .noneMatch(v -> "MSTG-NETWORK-4".equals(v.get("rule_id")) || "MASTG-TEST-0385".equals(v.get("rule_id"))));
        }
    }

    @Test
    void pinningIsReportedWhenTheAppTalksToTheNetworkWithoutPinning(@TempDir Path tmp) throws Exception {
        List<String> online = List.of("[NSURLSession sharedSession];");
        assertTrue(reported("MSTG-NETWORK-4", PackagePlatform.IOS, tmp.resolve("a.sqlite"), online, List.of()));
        assertTrue(reported("MASTG-TEST-0385", PackagePlatform.IOS, tmp.resolve("b.sqlite"), List.of("x"), List.of("https://api.example.com/v1")));
    }

    @Test
    void pinningIsNotReportedWhenPinningIsPresent(@TempDir Path tmp) throws Exception {
        List<String> pinned = List.of("[NSURLSession sharedSession]; SecTrustEvaluate(trust, &r); TrustKit");
        assertFalse(reported("MSTG-NETWORK-4", PackagePlatform.IOS, tmp.resolve("a.sqlite"), pinned, List.of()));
    }

    @Test
    void keyboardRuleNeedsATextInput(@TempDir Path tmp) throws Exception {
        assertFalse(reported("MASTG-TEST-0389", PackagePlatform.IOS, tmp.resolve("a.sqlite"), List.of("return;"), List.of()));
        assertTrue(reported("MASTG-TEST-0389", PackagePlatform.IOS, tmp.resolve("b.sqlite"), List.of("UITextField *t;"), List.of()));
    }

    @Test
    void gmsProviderRuleNeedsGms(@TempDir Path tmp) throws Exception {
        assertFalse(reported("MASTG-TEST-0295", PackagePlatform.ANDROID, tmp.resolve("a.sqlite"), List.of("class A {}"), List.of()));
        assertTrue(reported("MASTG-TEST-0295", PackagePlatform.ANDROID, tmp.resolve("b.sqlite"),
                List.of("import com.google.android.gms.common.GoogleApiAvailability;"), List.of()));
    }

    @Test
    void absenceRulesWithoutAPreconditionStillFire(@TempDir Path tmp) throws Exception {
        // anti-debug is a property of any binary, not of a feature the app may or may not use
        assertTrue(reported("MSTG-RESILIENCE-2", PackagePlatform.IOS, tmp.resolve("a.sqlite"), List.of("return;"), List.of()));
    }
}
