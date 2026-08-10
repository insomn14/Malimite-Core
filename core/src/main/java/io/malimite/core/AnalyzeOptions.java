package io.malimite.core;

import java.nio.file.Path;
import java.util.Map;

public record AnalyzeOptions(
        Path ipaPath,
        Path ghidraHome,
        Path outputDir,
        boolean llmEnabled,
        LlmMode llmMode,
        Map<String, String> llmConfig,
        Path jadxHome,
        boolean assessmentEnabled) {

    /** Alias for the uploaded package path (.ipa or .apk). */
    public Path packagePath() {
        return ipaPath;
    }

    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        private Path ipaPath, ghidraHome, outputDir, jadxHome;
        private boolean llmEnabled;
        private LlmMode llmMode = LlmMode.SUMMARIZE;
        private Map<String, String> llmConfig = Map.of();
        private boolean assessmentEnabled = true;

        public Builder ipaPath(Path p)      { this.ipaPath = p; return this; }
        /** Preferred alias — same as {@link #ipaPath(Path)}. */
        public Builder packagePath(Path p)  { this.ipaPath = p; return this; }
        public Builder ghidraHome(Path p)   { this.ghidraHome = p; return this; }
        public Builder jadxHome(Path p)     { this.jadxHome = p; return this; }
        public Builder outputDir(Path p)    { this.outputDir = p; return this; }
        public Builder llmEnabled(boolean b){ this.llmEnabled = b; return this; }
        public Builder llmMode(LlmMode m)   { this.llmMode = m; return this; }
        public Builder llmConfig(Map<String, String> c) { this.llmConfig = c; return this; }
        public Builder assessmentEnabled(boolean b) { this.assessmentEnabled = b; return this; }

        public AnalyzeOptions build() {
            if (ipaPath == null || outputDir == null)
                throw new IllegalArgumentException("packagePath and outputDir required");
            return new AnalyzeOptions(ipaPath, ghidraHome, outputDir, llmEnabled, llmMode, llmConfig,
                    jadxHome, assessmentEnabled);
        }
    }
}
