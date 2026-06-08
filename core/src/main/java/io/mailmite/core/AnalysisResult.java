package io.mailmite.core;

import java.nio.file.Path;

public record AnalysisResult(String scanId, Path reportDir, long durationMs, Path dbPath) {}
