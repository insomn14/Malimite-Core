package io.malimite.core;

import org.json.JSONObject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DeepSeekProviderTest {

    @Test void resolveModel_blankUsesDefault() {
        assertEquals(DeepSeekModels.DEFAULT, DeepSeekModels.resolve(""));
        assertEquals(DeepSeekModels.DEFAULT, DeepSeekModels.resolve(null));
    }

    @Test void resolveModel_knownIds() {
        assertEquals("deepseek-v4-pro", DeepSeekModels.resolve("deepseek-v4-pro"));
        assertEquals("deepseek-reasoner", DeepSeekModels.resolve("deepseek-reasoner"));
    }

    @Test void resolveModel_unknownPassedThrough() {
        assertEquals("custom-model", DeepSeekModels.resolve("custom-model"));
    }

    @Test void extractContent_prefersFinalAnswer() {
        JSONObject msg = new JSONObject()
                .put("reasoning_content", "thinking...")
                .put("content", "final answer");
        assertEquals("final answer", DeepSeekProvider.extractContent(msg));
    }

    @Test void extractContent_fallsBackToReasoning() {
        JSONObject msg = new JSONObject().put("reasoning_content", "chain of thought only");
        assertEquals("chain of thought only", DeepSeekProvider.extractContent(msg));
    }

    @Test void extractContent_emptyThrows() {
        assertThrows(LlmProvider.LlmException.class,
                () -> DeepSeekProvider.extractContent(new JSONObject()));
    }

    @Test void factoryCreatesDeepSeekProvider() {
        LlmProvider p = LlmProviderFactory.create(java.util.Map.of(
                "LLM_PROVIDER", "deepseek",
                "DEEPSEEK_API_KEY", "sk-test"));
        assertNotNull(p);
        assertInstanceOf(DeepSeekProvider.class, p);
        assertEquals(DeepSeekModels.DEFAULT, ((DeepSeekProvider) p).model());
    }

    @Test void factoryDeepSeekMissingKey() {
        assertThrows(IllegalStateException.class, () -> LlmProviderFactory.create(java.util.Map.of(
                "LLM_PROVIDER", "deepseek")));
    }
}
