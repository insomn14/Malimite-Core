package io.malimite.core;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link ClaudeOAuthProvider}'s pure helpers — no HTTP involved. Covers the
 * regression where a Claude 5+ model spends its entire {@code max_tokens} budget on extended
 * thinking and returns a {@code content} array with no {@code text} block at all (observed
 * directly: HTTP 200, {@code content[0].type == "thinking"}, {@code getJSONObject(0).getString("text")}
 * throwing "JSONObject[\"text\"] not found").
 */
class ClaudeOAuthProviderTest {

    @Test void extractText_findsTextBlockNotJustIndexZero() {
        JSONArray content = new JSONArray()
                .put(new JSONObject().put("type", "thinking").put("thinking", "").put("signature", "abc"))
                .put(new JSONObject().put("type", "text").put("text", "the real answer"));
        assertEquals("the real answer", ClaudeOAuthProvider.extractText(content, "end_turn"));
    }

    @Test void extractText_textAtIndexZeroStillWorks() {
        JSONArray content = new JSONArray()
                .put(new JSONObject().put("type", "text").put("text", "answer"));
        assertEquals("answer", ClaudeOAuthProvider.extractText(content, "end_turn"));
    }

    @Test void extractText_onlyThinkingBlockThrowsDiagnosableError() {
        JSONArray content = new JSONArray()
                .put(new JSONObject().put("type", "thinking").put("thinking", "").put("signature", "abc"));
        LlmProvider.LlmException e = assertThrows(LlmProvider.LlmException.class,
                () -> ClaudeOAuthProvider.extractText(content, "max_tokens"));
        assertTrue(e.getMessage().contains("max_tokens"), "should surface the stop_reason: " + e.getMessage());
        assertTrue(e.getMessage().contains("thinking"), "should name the block type seen: " + e.getMessage());
        assertTrue(e.getMessage().contains("extended thinking"),
                "should explain the likely cause: " + e.getMessage());
    }

    @Test void extractText_redactedThinkingBlockSkippedToo() {
        JSONArray content = new JSONArray()
                .put(new JSONObject().put("type", "redacted_thinking").put("data", "opaque"))
                .put(new JSONObject().put("type", "text").put("text", "final"));
        assertEquals("final", ClaudeOAuthProvider.extractText(content, "end_turn"));
    }

    @Test void extractText_emptyContentArrayThrows() {
        assertThrows(LlmProvider.LlmException.class,
                () -> ClaudeOAuthProvider.extractText(new JSONArray(), "end_turn"));
    }

    @Test void looksLikeUnsupportedThinkingDisabled_detectsAnthropicRejection() {
        // Representative of Anthropic's actual 400 body for a model that rejects thinking:disabled.
        String body = "{\"type\":\"error\",\"error\":{\"type\":\"invalid_request_error\"," +
                "\"message\":\"thinking.type: Input should be 'enabled' or 'adaptive' — "
                + "'disabled' is not supported for this model\"}}";
        assertTrue(ClaudeOAuthProvider.looksLikeUnsupportedThinkingDisabled(body));
    }

    @Test void looksLikeUnsupportedThinkingDisabled_falseForUnrelatedError() {
        String body = "{\"type\":\"error\",\"error\":{\"type\":\"invalid_request_error\"," +
                "\"message\":\"max_tokens: 999999 exceeds the model's maximum\"}}";
        assertFalse(ClaudeOAuthProvider.looksLikeUnsupportedThinkingDisabled(body));
    }

    @Test void looksLikeUnsupportedThinkingDisabled_nullBodySafe() {
        assertFalse(ClaudeOAuthProvider.looksLikeUnsupportedThinkingDisabled(null));
    }
}
