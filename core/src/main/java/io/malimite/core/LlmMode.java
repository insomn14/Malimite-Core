package io.malimite.core;

/** Analysis mode passed to the LLM enricher. Also selects {@link ScanScope}. */
public enum LlmMode {
    /** Reconstruct decompiled code. First-party scope (same as Fast Scan). */
    AUTO_FIX,
    /**
     * Fast Scan: first-party-only analysis (app packages + first-party native libs).
     * LLM prompt is a cheap summarize-style pass on in-scope code.
     */
    SUMMARIZE,
    /**
     * Full Scan: every ingested target including third-party Java/native.
     * LLM {@code FIND_VULNS} on everything in-scope (which is ALL).
     */
    FIND_VULNS,
    /**
     * Offensive playbooks: locate critical controls and emit Frida bypass/intercept scripts.
     * Requires LLM enrichment enabled; does not promote into Vulnerabilities / learned rules.
     * Scope is first-party union a narrow security-SDK allowlist.
     */
    OFFENSIVE;

    public static LlmMode fromString(String s) {
        if (s == null) return SUMMARIZE;
        return switch (s.toLowerCase().replace("-", "_").replace(" ", "_")) {
            case "auto_fix", "autofix", "fix" -> AUTO_FIX;
            case "find_vulns", "vulns", "vuln", "full", "full_scan", "fullscan" -> FIND_VULNS;
            case "offensive", "offense", "frida", "bypass" -> OFFENSIVE;
            case "summarize", "summary", "fast", "fast_scan", "fastscan" -> SUMMARIZE;
            default -> SUMMARIZE;
        };
    }

    /** FIRST_PARTY for Fast Scan / Auto Fix / Offensive; ALL for Full Scan. */
    public ScanScope scanScope() {
        return this == FIND_VULNS ? ScanScope.ALL : ScanScope.FIRST_PARTY;
    }

    /** Offensive re-includes a narrow root/RASP/pinning SDK allowlist. */
    public boolean includeSecuritySdks() {
        return this == OFFENSIVE;
    }

    public String displayLabel() {
        return switch (this) {
            case SUMMARIZE -> "Fast Scan";
            case FIND_VULNS -> "Full Scan";
            case AUTO_FIX -> "Auto Fix";
            case OFFENSIVE -> "Offensive";
        };
    }
}
