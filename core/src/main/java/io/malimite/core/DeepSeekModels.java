package io.malimite.core;

import java.util.List;
import java.util.Set;

/** Known DeepSeek chat model identifiers (OpenAI-compatible API). */
public final class DeepSeekModels {

    /** Fast default — DeepSeek-V4-Flash, 1M context. */
    public static final String V4_FLASH = "deepseek-v4-flash";

    /** Higher quality — DeepSeek-V4-Pro. */
    public static final String V4_PRO = "deepseek-v4-pro";

    /** Legacy alias for V4-Flash non-thinking mode (deprecated 2026-07-24). */
    public static final String CHAT = "deepseek-chat";

    /** Legacy alias for V4-Flash thinking mode (deprecated 2026-07-24). */
    public static final String REASONER = "deepseek-reasoner";

    public static final String DEFAULT = V4_FLASH;

    public static final List<String> ALL = List.of(V4_FLASH, V4_PRO, CHAT, REASONER);

    private static final Set<String> KNOWN = Set.copyOf(ALL);

    private DeepSeekModels() {}

    /** Returns {@code model} when non-blank and known; otherwise {@link #DEFAULT}. */
    public static String resolve(String model) {
        if (model == null || model.isBlank()) return DEFAULT;
        String trimmed = model.trim();
        return KNOWN.contains(trimmed) ? trimmed : trimmed;
    }

    public static boolean isReasoningModel(String model) {
        return REASONER.equals(model);
    }
}
