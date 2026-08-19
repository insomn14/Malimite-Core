package io.malimite.core;

/**
 * Which code the MSTG scanner, LLM enricher, and native Ghidra decompile consider
 * in-scope. Derived from {@link LlmMode} — not a prompt-only rename.
 *
 * <p>{@link AssessmentScanner} ignores this and always sees third-party SDK
 * markers needed for PRESENT/ABSENT inventory.
 */
public enum ScanScope {
    /** App packages / first-party native libs only (Fast Scan, Auto Fix, Offensive). */
    FIRST_PARTY,
    /** Everything ingested, including third-party Java and native (Full Scan). */
    ALL;

    public static ScanScope from(LlmMode mode) {
        if (mode == null) return FIRST_PARTY;
        return mode.scanScope();
    }
}
