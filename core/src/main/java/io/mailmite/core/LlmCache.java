package io.mailmite.core;

import java.util.Optional;

/**
 * Cache for LLM results keyed by SHA-256(decompiledCode + mode).
 * Prevents redundant API calls when a function hasn't changed between scans.
 */
public interface LlmCache {

    Optional<String> get(String hash);

    void put(String hash, String result);

    /** No-op implementation used by CLI and tests. */
    LlmCache NOOP = new LlmCache() {
        @Override public Optional<String> get(String hash) { return Optional.empty(); }
        @Override public void put(String hash, String result) {}
    };
}
