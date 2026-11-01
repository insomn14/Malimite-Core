# malimite-core

Headless analysis engine shared by the CLI, the web service, and the Slack bot — all three call
`MalimiteAnalyzer.analyze()` rather than re-implementing decompile/scan/report logic. No Swing/AWT;
originally ported from upstream [Malimite](https://github.com/LaurieWired/Malimite) (see the root
[`README.md`](../README.md#why-malimite) and [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md)
for attribution), since grown well beyond the original port. The extraction checklist that used to
live here is long finished; see [`PHASES.md`](../PHASES.md) for the full development history.

## Module map

| Area | Key classes |
|---|---|
| **Entry point** | `MalimiteAnalyzer` (orchestrates the whole pipeline), `AnalyzeOptions` (input, builder-style), `AnalysisResult` / `AnalysisReport` (output) |
| **Package handling** | `IpaExtractor` / `IpaValidator` / `Macho` / `InfoPlist` / `MobileProvision` (iOS); `ApkExtractor` / `ApkValidator` / `AndroidManifestParser` / `XapkBundle` (Android); `BinaryIdentity`, `ResourceParser`, `PlistUtils` |
| **Decompilation** | `GhidraRunner` (headless `analyzeHeadless` + socket IPC), `GhidraOnDemand` (persistent project, single-class re-decompile), `JadxRunner` / `JadxIngest` (Android DEX → Java), `AscRunner` (Droid ASC backend), `OnDemandDecompiler` (shared by the AI Assistant and the Functions tab), `MachoLightIngest` (strings/symbols only, no Ghidra — backs `--ios-light`), `SyntaxParser` / `DemangleSwift` |
| **Detection** | `VulnerabilityScanner` + `VulnerabilityCatalog` (iOS MASTG/MSTG), `AndroidVulnerabilityCatalog` (Android MASTG), `VulnerabilityRule`, `ScanScope` / `ScanScopeFilter` (Fast/Full/Auto Fix/Offensive scoping), `RuleQuality` (gates for LLM-learned rules), `ObfuscationSignals`, `ElfNativeProtections`, `AndroidLibraryDefinitions` / `AndroidNativeLibraryDefinitions` / `LibraryDefinitions` (first/third-party classification) |
| **Security Assessment** | `AssessmentScanner`, `AssessmentCatalog`, `AssessmentResult`, `AssessmentStatus` (PRESENT/PARTIAL/ABSENT/UNKNOWN controls inventory, separate from vulnerability findings) |
| **LLM providers** | `LlmProvider` (interface), `LlmProviderFactory`, `OpenAiProvider`, `ClaudeProvider`, `ClaudeOAuthProvider` (+ `AnthropicOAuthCredentials` / `AnthropicOAuthLogin` for `malimite claude-login`), `DeepSeekProvider` / `DeepSeekModels`, `OllamaProvider`, `LlmEnricher` (per-function enrichment + AI Fix's prompt infra is on the Python side, see `web/app/finding_fix.py`), `LlmMode`, `LlmCache`, `LearnedRulesStore` |
| **Persistence** | `SqliteStore` (the `analysis.sqlite` schema: classes, functions, strings, vulnerabilities incl. triage/AI-Fix overrides, LLM findings, assessments) |
| **Reporting** | `ReportBuilder` (assembles `AnalysisReport` from `SqliteStore`), `HtmlReporter` (`report.html`), `SarifExporter` (`findings.sarif`), `ReportRenderer` (CLI entry for regenerating reports without a full re-scan) |
| **Platform** | `PackagePlatform` (IOS/ANDROID), `CoreConfig` (env var / system property resolution) |

## Public API

```java
AnalyzeOptions opts = AnalyzeOptions.builder()
    .packagePath(Path.of("app.ipa"))     // .ipa, .apk, or .xapk
    .ghidraHome(Path.of("/opt/ghidra"))  // required for .ipa / Android arm64 .so
    .jadxHome(Path.of("/opt/jadx"))      // required for Android DEX
    .outputDir(Path.of("./out"))
    .assessmentEnabled(true)             // Security Assessment inventory (default: true)
    .llmEnabled(false)
    // .llmMode(LlmMode.SUMMARIZE)       // scan scope even without LLM — see README.md "Detection engines"
    // .iosLight(true)                   // iOS only: skip Ghidra for binaries too large to auto-analyze
    // .decompiler("asc")                // Android: "jadx" (default) or "asc" (Droid ASC)
    .build();

AnalysisResult result = new MalimiteAnalyzer().analyze(opts);
```

See the root [`README.md`](../README.md) for the full CLI flag / environment variable reference,
the web service, and the detection engines these options drive.
