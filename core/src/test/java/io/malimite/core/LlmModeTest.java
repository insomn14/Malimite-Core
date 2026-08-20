package io.malimite.core;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class LlmModeTest {

    @Test void fromString_null_defaultsSummarize() {
        assertEquals(LlmMode.SUMMARIZE, LlmMode.fromString(null));
    }

    @Test void fromString_variants() {
        assertEquals(LlmMode.FIND_VULNS, LlmMode.fromString("find_vulns"));
        assertEquals(LlmMode.FIND_VULNS, LlmMode.fromString("VULNS"));
        assertEquals(LlmMode.FIND_VULNS, LlmMode.fromString("full"));
        assertEquals(LlmMode.FIND_VULNS, LlmMode.fromString("full_scan"));
        assertEquals(LlmMode.FIND_VULNS, LlmMode.fromString("full-scan"));
        assertEquals(LlmMode.AUTO_FIX,   LlmMode.fromString("autofix"));
        assertEquals(LlmMode.AUTO_FIX,   LlmMode.fromString("AUTO_FIX"));
        assertEquals(LlmMode.SUMMARIZE,  LlmMode.fromString("summarize"));
        assertEquals(LlmMode.SUMMARIZE,  LlmMode.fromString("summary"));
        assertEquals(LlmMode.SUMMARIZE,  LlmMode.fromString("fast"));
        assertEquals(LlmMode.SUMMARIZE,  LlmMode.fromString("fast_scan"));
        assertEquals(LlmMode.SUMMARIZE,  LlmMode.fromString("fastscan"));
        assertEquals(LlmMode.SUMMARIZE,  LlmMode.fromString("FAST-SCAN"));
        assertEquals(LlmMode.SUMMARIZE,  LlmMode.fromString("unknown"));
        assertEquals(LlmMode.OFFENSIVE,  LlmMode.fromString("offensive"));
        assertEquals(LlmMode.OFFENSIVE,  LlmMode.fromString("offense"));
        assertEquals(LlmMode.OFFENSIVE,  LlmMode.fromString("frida"));
        assertEquals(LlmMode.OFFENSIVE,  LlmMode.fromString("bypass"));
        assertEquals(LlmMode.OFFENSIVE,  LlmMode.fromString("OFFENSIVE"));
    }

    @Test void scanScopeDerivedFromMode() {
        assertEquals(ScanScope.FIRST_PARTY, LlmMode.SUMMARIZE.scanScope());
        assertEquals(ScanScope.FIRST_PARTY, LlmMode.AUTO_FIX.scanScope());
        assertEquals(ScanScope.FIRST_PARTY, LlmMode.OFFENSIVE.scanScope());
        assertEquals(ScanScope.ALL, LlmMode.FIND_VULNS.scanScope());
        assertTrue(LlmMode.OFFENSIVE.includeSecuritySdks());
        assertFalse(LlmMode.SUMMARIZE.includeSecuritySdks());
        assertEquals("Fast Scan", LlmMode.SUMMARIZE.displayLabel());
        assertEquals("Full Scan", LlmMode.FIND_VULNS.displayLabel());
        assertEquals("Auto Fix", LlmMode.AUTO_FIX.displayLabel());
        assertEquals("Offensive", LlmMode.OFFENSIVE.displayLabel());
    }
}
