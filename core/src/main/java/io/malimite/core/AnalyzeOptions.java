package io.malimite.core;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

public record AnalyzeOptions(
        Path ipaPath,
        Path ghidraHome,
        Path outputDir,
        boolean llmEnabled,
        LlmMode llmMode,
        Map<String, String> llmConfig,
        Path jadxHome,
        boolean assessmentEnabled,
        List<String> extraPackagePrefixes,
        int maxEnrichFunctions,
        /** Decompiler backend: {@code jadx} (default) or {@code asc} (Droid ASC). */
        String decompiler,
        /** Droid ASC source checkout dir (else ASC_HOME env, else `droidasc` on PATH). */
        Path ascHome,
        /** Cap classes decompiled via ASC (0 = no cap). */
        int maxAscClasses,
        /** Parallel ASC getclass workers. */
        int decompileThreads) {

    public AnalyzeOptions {
        if (llmMode == null) llmMode = LlmMode.SUMMARIZE;
        if (llmConfig == null) llmConfig = Map.of();
        extraPackagePrefixes = extraPackagePrefixes == null
                ? List.of()
                : List.copyOf(extraPackagePrefixes);
        if (decompiler == null || decompiler.isBlank()) decompiler = "jadx";
        if (decompileThreads <= 0) decompileThreads = 8;
    }

    /** True when the Droid ASC backend was requested. */
    public boolean useAsc() {
        return "asc".equalsIgnoreCase(decompiler);
    }

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
        private List<String> extraPackagePrefixes = List.of();
        private int maxEnrichFunctions = 0;
        private String decompiler = "jadx";
        private Path ascHome;
        private int maxAscClasses = 0;
        private int decompileThreads = 8;

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
        public Builder extraPackagePrefixes(List<String> p) {
            this.extraPackagePrefixes = p;
            return this;
        }
        /** Cap the number of functions the LLM enricher inspects (0 = no cap). */
        public Builder maxEnrichFunctions(int n) { this.maxEnrichFunctions = n; return this; }

        /** Decompiler backend: {@code jadx} or {@code asc}. */
        public Builder decompiler(String d) { this.decompiler = d; return this; }
        /** Droid ASC checkout dir (null → ASC_HOME env / PATH). */
        public Builder ascHome(Path p) { this.ascHome = p; return this; }
        /** Cap classes decompiled via ASC (0 = no cap). */
        public Builder maxAscClasses(int n) { this.maxAscClasses = n; return this; }
        /** Parallel ASC getclass workers. */
        public Builder decompileThreads(int n) { this.decompileThreads = n; return this; }

        public AnalyzeOptions build() {
            if (ipaPath == null || outputDir == null)
                throw new IllegalArgumentException("packagePath and outputDir required");
            return new AnalyzeOptions(ipaPath, ghidraHome, outputDir, llmEnabled, llmMode, llmConfig,
                    jadxHome, assessmentEnabled, extraPackagePrefixes, maxEnrichFunctions,
                    decompiler, ascHome, maxAscClasses, decompileThreads);
        }
    }
}
