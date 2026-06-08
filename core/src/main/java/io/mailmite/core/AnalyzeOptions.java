package io.mailmite.core;

import java.nio.file.Path;
import java.util.Map;

public record AnalyzeOptions(
        Path ipaPath,
        Path ghidraHome,
        Path outputDir,
        boolean llmEnabled,
        LlmMode llmMode,
        Map<String, String> llmConfig) {

    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        private Path ipaPath, ghidraHome, outputDir;
        private boolean llmEnabled;
        private LlmMode llmMode = LlmMode.SUMMARIZE;
        private Map<String, String> llmConfig = Map.of();

        public Builder ipaPath(Path p)      { this.ipaPath = p; return this; }
        public Builder ghidraHome(Path p)   { this.ghidraHome = p; return this; }
        public Builder outputDir(Path p)    { this.outputDir = p; return this; }
        public Builder llmEnabled(boolean b){ this.llmEnabled = b; return this; }
        public Builder llmMode(LlmMode m)   { this.llmMode = m; return this; }
        public Builder llmConfig(Map<String, String> c) { this.llmConfig = c; return this; }
        public AnalyzeOptions build() {
            if (ipaPath == null || ghidraHome == null || outputDir == null)
                throw new IllegalArgumentException("ipaPath, ghidraHome, outputDir required");
            return new AnalyzeOptions(ipaPath, ghidraHome, outputDir, llmEnabled, llmMode, llmConfig);
        }
    }
}
