package io.malimite.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LearnedRulesPlatformTest {

    @TempDir Path tmp;

    @Test
    void migratesMissingPlatformToIosOnLoad() throws Exception {
        Path iosFile = tmp.resolve("learned_rules.json");
        Files.writeString(iosFile, """
                {
                  "rules": [
                    {
                      "id": "LLM-XSS-001",
                      "scope": "XSS",
                      "title": "Old rule",
                      "category": "PLATFORM",
                      "severity": "HIGH",
                      "cvssScore": 7.0,
                      "cwe": "CWE-79",
                      "description": "d",
                      "remediation": "r",
                      "referenceUrl": "x",
                      "target": "DECOMPILED",
                      "regex": "evilPatternXYZ123",
                      "pocTemplate": "p",
                      "createdAt": 1
                    }
                  ]
                }
                """);

        LearnedRulesStore store = new LearnedRulesStore(iosFile, PackagePlatform.IOS);
        assertEquals(1, store.size());
        List<VulnerabilityRule> rules = store.asVulnerabilityRules();
        assertEquals(1, rules.size());
        assertEquals(VulnerabilityRule.Platform.IOS, rules.get(0).platform());

        String rewritten = Files.readString(iosFile);
        assertTrue(rewritten.contains("\"platform\": \"IOS\"") || rewritten.contains("\"platform\":\"IOS\""));
    }

    @Test
    void androidDefaultPathDistinctFromIos() {
        Path ios = LearnedRulesStore.defaultPath(PackagePlatform.IOS);
        Path and = LearnedRulesStore.defaultPath(PackagePlatform.ANDROID);
        assertTrue(and.toString().contains("learned_rules_android"));
        assertTrue(ios.toString().endsWith("learned_rules.json")
                || ios.toString().contains("learned_rules"));
        assertTrue(!ios.equals(and));
    }

    @Test
    void androidStorePersistsPlatformAndroid(@TempDir Path dir) {
        Path f = dir.resolve("learned_rules_android.json");
        LearnedRulesStore store = new LearnedRulesStore(f, PackagePlatform.ANDROID);
        String id = store.addRule("XSS", "t", "PLATFORM", "HIGH", 7.0, "CWE-79",
                "d", "r", "DECOMPILED", "uniqueAndroidRegex999", "poc", "ref");
        assertTrue(id != null);
        LearnedRulesStore reloaded = new LearnedRulesStore(f, PackagePlatform.ANDROID);
        assertEquals(VulnerabilityRule.Platform.ANDROID,
                reloaded.asVulnerabilityRules().get(0).platform());
    }
}
