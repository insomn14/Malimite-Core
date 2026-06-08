package io.mailmite.core;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class LlmModeTest {

    @Test void fromString_null_defaultsSummarize() {
        assertEquals(LlmMode.SUMMARIZE, LlmMode.fromString(null));
    }

    @Test void fromString_variants() {
        assertEquals(LlmMode.FIND_VULNS, LlmMode.fromString("find_vulns"));
        assertEquals(LlmMode.FIND_VULNS, LlmMode.fromString("VULNS"));
        assertEquals(LlmMode.AUTO_FIX,   LlmMode.fromString("autofix"));
        assertEquals(LlmMode.AUTO_FIX,   LlmMode.fromString("AUTO_FIX"));
        assertEquals(LlmMode.SUMMARIZE,  LlmMode.fromString("summarize"));
        assertEquals(LlmMode.SUMMARIZE,  LlmMode.fromString("unknown"));
    }
}
