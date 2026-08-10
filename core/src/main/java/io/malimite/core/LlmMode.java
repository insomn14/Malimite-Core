package io.malimite.core;

/** Analysis mode passed to the LLM enricher. */
public enum LlmMode {
    /** Translate decompiled code to idiomatic Swift/Objective-C (iOS) or Java (Android). */
    AUTO_FIX,
    /** Summarise what a function does in plain English. */
    SUMMARIZE,
    /** Identify security vulnerabilities and exploitation paths. */
    FIND_VULNS;

    public static LlmMode fromString(String s) {
        if (s == null) return SUMMARIZE;
        return switch (s.toLowerCase().replace("-", "_").replace(" ", "_")) {
            case "auto_fix", "autofix", "fix"  -> AUTO_FIX;
            case "find_vulns", "vulns", "vuln" -> FIND_VULNS;
            default                            -> SUMMARIZE;
        };
    }
}
