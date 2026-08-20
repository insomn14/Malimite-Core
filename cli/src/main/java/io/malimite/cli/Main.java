package io.malimite.cli;

import io.malimite.core.*;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.IVersionProvider;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Callable;

@Command(name = "malimite",
         mixinStandardHelpOptions = true,
         versionProvider = Main.ManifestVersionProvider.class,
         description = "Headless IPA/APK analyzer (Ghidra for iOS, JADX for Android).")
public class Main implements Callable<Integer> {

    public static final class ManifestVersionProvider implements IVersionProvider {
        private static final String DEVELOPMENT_VERSION = "malimite (development build)";

        @Override
        public String[] getVersion() {
            return new String[]{versionLine(Main.class.getPackage().getImplementationVersion())};
        }

        static String versionLine(String implementationVersion) {
            if (implementationVersion == null || implementationVersion.isBlank()) {
                return DEVELOPMENT_VERSION;
            }
            return "malimite " + implementationVersion;
        }
    }

    @Parameters(index = "0", description = "IPA or APK file to analyze")
    private Path ipa;

    @Option(names = {"-g", "--ghidra"}, description = "Ghidra install dir (required for .ipa)",
            defaultValue = "${env:GHIDRA_HOME}")
    private Path ghidraHome;

    @Option(names = {"-j", "--jadx"}, description = "JADX install dir or binary (or env JADX_HOME / JADX_PATH)",
            defaultValue = "${env:JADX_HOME}")
    private Path jadxHome;

    @Option(names = {"-o", "--out"}, description = "Output directory",
            defaultValue = "./malimite-out")
    private Path out;

    // LLM options (Phase 4)
    @Option(names = "--llm", description = "Enable LLM enrichment")
    private boolean llm;

    @Option(names = "--llm-provider",
            description = "LLM provider: openai|claude|deepseek|ollama  (env: LLM_PROVIDER)",
            defaultValue = "${env:LLM_PROVIDER:-none}")
    private String llmProvider;

    @Option(names = "--llm-mode",
            description = "Enrichment mode: summarize|auto_fix|find_vulns|offensive  (default: summarize)",
            defaultValue = "${env:LLM_MODE:-summarize}")
    private String llmModeStr;

    @Option(names = "--llm-model",
            description = "Override model id per provider  (env: LLM_MODEL)",
            defaultValue = "${env:LLM_MODEL:-}")
    private String llmModel;

    // picocli 4.7.6: negatable booleans need fallbackValue so --assessment sets true
    // (defaultValue alone inverts: --assessment→false, --no-assessment→true).
    @Option(names = "--assessment", negatable = true,
            description = "Run security-controls Assessment inventory (default: true)",
            fallbackValue = "true")
    private boolean assessment = true;

    // Reporting options (Phase 5)
    @Option(names = "--sarif", description = "Write SARIF 2.1 to <out>/findings.sarif",
            defaultValue = "false")
    private boolean sarif;

    @Option(names = "--html", description = "Write HTML report to <out>/report.html",
            defaultValue = "false")
    private boolean html;

    @Option(names = "--fail-on",
            description = "Exit 1 if SARIF results reach this severity: HIGH|MEDIUM|LOW",
            defaultValue = "NONE")
    private String failOn;

    @Override
    public Integer call() throws Exception {
        LlmMode mode = LlmMode.fromString(llmModeStr);
        if (mode == LlmMode.OFFENSIVE && !llm) {
            System.err.println("error: --llm-mode offensive requires --llm (LLM enrichment is mandatory for Offensive mode)");
            return 2;
        }

        Map<String, String> llmCfg = buildLlmConfig();
        AnalyzeOptions opts = AnalyzeOptions.builder()
                .packagePath(ipa)
                .ghidraHome(ghidraHome)
                .jadxHome(jadxHome)
                .outputDir(out)
                .llmEnabled(llm)
                .llmMode(mode)
                .llmConfig(llmCfg)
                .assessmentEnabled(assessment)
                .build();

        AnalysisResult r = new MalimiteAnalyzer().analyze(opts);

        // Build structured report from the SQLite written by the analyzer
        AnalysisReport report = ReportBuilder.buildFromDir(r.reportDir(), r.durationMs());

        System.out.println("scan_id=" + r.scanId());
        System.out.println("report=" + r.reportDir());
        System.out.printf("classes=%d  functions=%d  strings=%d%n",
                report.classCount(), report.functionCount(), report.stringCount());
        if (!report.entryPoints().isEmpty())
            System.out.println("entry_points=" + report.entryPoints());
        System.out.println("duration_ms=" + r.durationMs());

        // SARIF output
        Path sarifPath = null;
        if (sarif || !failOn.equalsIgnoreCase("NONE")) {
            sarifPath = SarifExporter.export(report, r.reportDir());
            System.out.println("sarif=" + sarifPath);
        }

        // HTML output
        if (html) {
            Path htmlPath = HtmlReporter.generate(report, r.reportDir());
            System.out.println("html=" + htmlPath);
        }

        // Exit code policy (Phase 5.4)
        return computeExitCode(report, failOn);
    }

    private int computeExitCode(AnalysisReport report, String failOn) {
        if ("NONE".equalsIgnoreCase(failOn)) return 0;
        if (report.llmFindings() == null || report.llmFindings().isEmpty()) return 0;

        boolean hasHigh   = report.llmFindings().stream()
                .anyMatch(f -> f.finding() != null && f.finding().toUpperCase().contains("HIGH"));
        boolean hasMedium = report.llmFindings().stream()
                .anyMatch(f -> f.finding() != null && f.finding().toUpperCase().contains("MEDIUM"));
        boolean hasAny    = !report.llmFindings().isEmpty();

        return switch (failOn.toUpperCase()) {
            case "HIGH"   -> hasHigh   ? 1 : 0;
            case "MEDIUM" -> (hasHigh || hasMedium) ? 1 : 0;
            case "LOW"    -> hasAny    ? 1 : 0;
            default       -> 0;
        };
    }

    private Map<String, String> buildLlmConfig() {
        Map<String, String> cfg = new HashMap<>();
        cfg.put("LLM_PROVIDER",      llmProvider);
        cfg.put("LLM_MODEL",         llmModel == null ? "" : llmModel);
        cfg.put("LLM_MAX_TOKENS",    envOr("LLM_MAX_TOKENS", "4096"));
        cfg.put("OPENAI_API_KEY",      envOr("OPENAI_API_KEY", ""));
        cfg.put("ANTHROPIC_API_KEY",   envOr("ANTHROPIC_API_KEY", ""));
        cfg.put("DEEPSEEK_API_KEY",    envOr("DEEPSEEK_API_KEY", ""));
        cfg.put("DEEPSEEK_BASE_URL",   envOr("DEEPSEEK_BASE_URL", "https://api.deepseek.com"));
        cfg.put("OLLAMA_BASE_URL",     envOr("OLLAMA_BASE_URL", "http://localhost:11434"));
        return cfg;
    }

    private static String envOr(String key, String def) {
        String v = System.getenv(key);
        return v != null ? v : def;
    }

    public static void main(String[] args) {
        System.exit(new CommandLine(new Main()).execute(args));
    }
}
