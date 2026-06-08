package io.mailmite.core;

/** Thin abstraction over an LLM backend. */
public interface LlmProvider {
    /**
     * Send a prompt and return the model's text response.
     * Throws {@link LlmException} on HTTP or parsing errors.
     */
    String complete(String systemPrompt, String userMessage) throws LlmException;

    class LlmException extends RuntimeException {
        public LlmException(String msg)            { super(msg); }
        public LlmException(String msg, Throwable t) { super(msg, t); }
    }
}
