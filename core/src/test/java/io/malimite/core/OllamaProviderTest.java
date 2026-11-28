package io.malimite.core;

import org.json.JSONObject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class OllamaProviderTest {

    @Test
    void defaultsRaiseContextAndDisableThinking() {
        JSONObject b = new OllamaProvider("http://h:11434", "qwen3.5:4b", 4096).buildBody("S", "U");
        assertEquals(16384, b.getJSONObject("options").getInt("num_ctx"));
        assertEquals(4096, b.getJSONObject("options").getInt("num_predict"));   // LLM_MAX_TOKENS
        assertFalse(b.getBoolean("think"));
        assertEquals("30m", b.getString("keep_alive"));
    }

    @Test
    void optionsJsonOverridesAndNumPredictWins() {
        JSONObject b = new OllamaProvider("http://h:11434", "m", 4096,
                "{\"num_ctx\":8192,\"num_predict\":1000,\"temperature\":0.7,\"think\":true,\"keep_alive\":\"-1\"}")
                .buildBody("S", "U");
        JSONObject o = b.getJSONObject("options");
        assertEquals(8192, o.getInt("num_ctx"));
        assertEquals(1000, o.getInt("num_predict"));
        assertEquals(0.7, o.getDouble("temperature"), 1e-9);
        assertEquals(true, b.getBoolean("think"));
        assertEquals("-1", b.getString("keep_alive"));
    }

    @Test
    void malformedOptionsFallBackToDefaults() {
        JSONObject b = new OllamaProvider("http://h:11434", "m", 4096, "{oops").buildBody("S", "U");
        assertEquals(16384, b.getJSONObject("options").getInt("num_ctx"));
    }
}
