# mailmite-core

Headless port of Malimite's analysis pipeline.

## TODO: Extraction from upstream

The following classes from `Malimite-src/src/main/java/com/lauriewired/malimite/`
need to be ported into `io.mailmite.core` with **Swing/AWT references stripped**:

| Upstream class                        | Target                                 | Notes                          |
|---------------------------------------|----------------------------------------|--------------------------------|
| `Malimite.java` (main)                | `MailmiteAnalyzer.java`                | Strip Swing, expose analyze()  |
| `configuration/Config.java`           | `config/CoreConfig.java`               | Replace File-based w/ Builder  |
| `decompile/GhidraProject.java`        | `decompile/GhidraRunner.java`          | user.dir → injected path       |
| `decompile/SyntaxParser.java`         | (unchanged)                            | already headless               |
| `decompile/DemangleSwift.java`        | (unchanged)                            |                                |
| `decompile/DynamicDecompile.java`     | (unchanged)                            |                                |
| `database/SQLiteDBHandler.java`       | `store/SqliteStore.java`               | + add `PostgresStore` impl     |
| `files/Macho.java`, `InfoPlist.java`  | `files/*`                              | unchanged                      |
| `utils/FileProcessing.java`           | `util/IpaExtractor.java`               | drop GUI callbacks             |
| `tools/AIBackend.java`                | `enrich/LlmEnricher.java`              | inject API key from env        |
| `DecompilerBridge/ghidra/DumpClassData.java` | `scripts/DumpClassData.java`    | copy as-is into resources      |

## Public API

    AnalyzeOptions opts = AnalyzeOptions.builder()
        .ipaPath(Path.of("app.ipa"))
        .ghidraHome(Path.of("/opt/ghidra"))
        .outputDir(Path.of("./out"))
        .llmEnabled(false)
        .build();

    AnalysisResult result = new MailmiteAnalyzer().analyze(opts);
