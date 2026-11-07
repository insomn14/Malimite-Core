package io.malimite.core;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** LlmProviderFactory coverage for the two providers the Config tab added: bedrock and glm.
 * See DeepSeekProviderTest for the equivalent coverage pattern on an existing provider. */
class LlmProviderFactoryBedrockGlmTest {

    @Test void factoryCreatesBedrockProvider() {
        LlmProvider p = LlmProviderFactory.create(Map.of(
                "LLM_PROVIDER", "bedrock",
                "AWS_ACCESS_KEY_ID", "AKIAFAKEEXAMPLE",
                "AWS_SECRET_ACCESS_KEY", "fakeSecretExample"));
        assertNotNull(p);
        assertInstanceOf(BedrockProvider.class, p);
        BedrockProvider bp = (BedrockProvider) p;
        assertEquals("us-east-1", bp.region());                     // default when AWS_REGION absent
        assertTrue(bp.model().startsWith("anthropic.claude-"));     // default model id
    }

    @Test void factoryBedrockHonorsRegionAndModelOverrides() {
        LlmProvider p = LlmProviderFactory.create(Map.of(
                "LLM_PROVIDER", "bedrock",
                "AWS_ACCESS_KEY_ID", "AKIAFAKEEXAMPLE",
                "AWS_SECRET_ACCESS_KEY", "fakeSecretExample",
                "AWS_REGION", "eu-west-1",
                "BEDROCK_MODEL_ID", "anthropic.claude-opus-5-20260101-v1:0"));
        BedrockProvider bp = (BedrockProvider) p;
        assertEquals("eu-west-1", bp.region());
        assertEquals("anthropic.claude-opus-5-20260101-v1:0", bp.model());
    }

    @Test void factoryBedrockMissingAccessKeyThrows() {
        assertThrows(IllegalStateException.class, () -> LlmProviderFactory.create(Map.of(
                "LLM_PROVIDER", "bedrock",
                "AWS_SECRET_ACCESS_KEY", "fakeSecretExample")));
    }

    @Test void factoryBedrockMissingSecretThrows() {
        assertThrows(IllegalStateException.class, () -> LlmProviderFactory.create(Map.of(
                "LLM_PROVIDER", "bedrock",
                "AWS_ACCESS_KEY_ID", "AKIAFAKEEXAMPLE")));
    }

    @Test void factoryCreatesGlmProvider() {
        LlmProvider p = LlmProviderFactory.create(Map.of(
                "LLM_PROVIDER", "glm",
                "GLM_API_KEY", "fake-glm-key"));
        assertNotNull(p);
        assertInstanceOf(GlmProvider.class, p);
        assertEquals("glm-4.6", ((GlmProvider) p).model());
    }

    @Test void factoryGlmHonorsModelAndBaseUrlOverrides() {
        LlmProvider p = LlmProviderFactory.create(Map.of(
                "LLM_PROVIDER", "glm",
                "GLM_API_KEY", "fake-glm-key",
                "LLM_MODEL", "glm-4.5-air",
                "GLM_BASE_URL", "https://example.test/v4"));
        GlmProvider gp = (GlmProvider) p;
        assertEquals("glm-4.5-air", gp.model());
        assertEquals("https://example.test/v4/chat/completions", gp.completionsUrl());
    }

    @Test void factoryGlmMissingKeyThrows() {
        assertThrows(IllegalStateException.class, () -> LlmProviderFactory.create(Map.of(
                "LLM_PROVIDER", "glm")));
    }

    @Test void factoryUnknownProviderReturnsNull() {
        assertNull(LlmProviderFactory.create(Map.of("LLM_PROVIDER", "not-a-real-provider")));
    }

    @Test void factoryNoneReturnsNull() {
        assertNull(LlmProviderFactory.create(Map.of()));
        assertNull(LlmProviderFactory.create(Map.of("LLM_PROVIDER", "none")));
    }
}
