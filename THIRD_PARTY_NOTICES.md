# Third-party notices

Malimite-Core is licensed under the Apache License 2.0 (see [`LICENSE`](LICENSE)). It stands on the work of the
projects below. This file lists what is **bundled** into Malimite-Core's artifacts, what it **invokes** as external
tools, and what it **derives** from. Licenses are those declared by each project; check upstream for the current text.
This is an attribution list, not legal advice.

## Origin

| Project | License | What we took |
|---|---|---|
| [**Malimite**](https://github.com/LaurieWired/Malimite) by [LaurieWired](https://github.com/LaurieWired) | Apache-2.0 | The Ghidra-backed analysis design, ported without Swing: `GhidraProject` → `GhidraRunner`, `DynamicDecompile`/`FileProcessing` → `MalimiteAnalyzer`/`IpaExtractor`, `AIBackend` → `LlmEnricher`, `DumpClassData.java` → the bundled Ghidra post-script, `SQLiteDBHandler` → `SqliteStore`. These files are derived and have been modified; upstream publishes no `NOTICE` file. |

Droid ASC, the Android decompiler backend described below, was inspired by [**MG1937/ASC**](https://github.com/MG1937/ASC)
("a super FAST Android decompiler front-end designed for Agents/Mobile Researchers", Apache-2.0).

## Decompilers and analysis tools (invoked as external programs, not bundled)

| Tool | License | Role |
|---|---|---|
| [**Ghidra**](https://github.com/NationalSecurityAgency/ghidra) (NSA) | Apache-2.0 | Headless decompilation of iOS Mach-O binaries and Android `lib/arm64-v8a/*.so` (`analyzeHeadless`). The Docker image downloads an official release (12.0.4). |
| [**JADX**](https://github.com/skylot/jadx) (skylot) | Apache-2.0 | Android DEX → Java decompilation, including single-class decompilation for the AI Assistant. The Docker image downloads an official release. |
| **Droid ASC** (`droidasc` on [PyPI](https://pypi.org/project/droidasc/)) | Apache-2.0 | Optional on-demand Android decompiler backend (`--decompiler asc`) and the `asc` option of the AI Assistant's `decompile` tool. Developed by the author of Malimite-Core (insomn14) as a separate, independently released package, and inspired by [**MG1937/ASC**](https://github.com/MG1937/ASC) (Apache-2.0). Overview: [*Droid ASC: R8 Compiler Optimization as a Decompiler Primitive*](https://blackhat.com/europe/arsenal/schedule/index.html#droid-asc-r8-compiler-optimization-as-a-decompiler-primitive-54834) (Black Hat Europe Arsenal). It builds on [Androguard](https://github.com/androguard/androguard) (Apache-2.0). |

## Standards and content

| Source | License | Use |
|---|---|---|
| [**OWASP MASTG / MASVS**](https://mas.owasp.org/) | CC BY-SA 4.0 | The detection catalogs (`VulnerabilityCatalog`, `AndroidVulnerabilityCatalog`, `AssessmentCatalog`) are derived from MASTG tests; rule IDs (`MASTG-TEST-*`, legacy `MSTG-*`), titles and reference URLs come from it. Credit to the OWASP MAS project and contributors; derived descriptions fall under CC BY-SA 4.0. |
| [**SARIF 2.1.0**](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) (OASIS) | OASIS IPR | Output format of `findings.sarif`. |
| [**ANTLR grammars-v4**](https://github.com/antlr/grammars-v4) `cpp/CPP14*.g4` | MIT | The C++14 grammar (`core/src/main/antlr4/…/CPP14Lexer.g4`, `CPP14Parser.g4`) used to parse decompiled pseudocode, carried over from upstream Malimite. |

## Java libraries bundled in the CLI fat JAR

| Library | License |
|---|---|
| [dd-plist](https://github.com/3breadt/dd-plist) | MIT |
| [apk-parser](https://github.com/hsiafan/apk-parser) (net.dongliu) | BSD 2-Clause |
| [sqlite-jdbc](https://github.com/xerial/sqlite-jdbc) (Xerial) | Apache-2.0 |
| [org.json (JSON-java)](https://github.com/stleary/JSON-java) 20231013 | Public Domain |
| [Gson](https://github.com/google/gson) | Apache-2.0 |
| [picocli](https://github.com/remkop/picocli) | Apache-2.0 |
| [ANTLR 4 runtime](https://github.com/antlr/antlr4) | BSD 3-Clause |
| [SLF4J](https://www.slf4j.org/) (`slf4j-simple`) | MIT |

The legacy `api/`, `worker/`, `watcher/` and `bot/` modules additionally use Javalin (Apache-2.0), Jedis (MIT), the MinIO
Java SDK (Apache-2.0) and Jackson (Apache-2.0).

## Python dependencies (web service and Slack bot)

FastAPI (MIT), Starlette (BSD 3-Clause), Uvicorn (BSD 3-Clause), Pydantic and pydantic-settings (MIT), httpx
(BSD 3-Clause), aiosqlite (MIT), aiofiles (Apache-2.0), python-multipart (Apache-2.0), Slack Bolt and Slack SDK for
Python (MIT), python-dotenv (BSD 3-Clause).

## Frontend assets (vendored in `web/vendor/`, served to the browser)

| Library | License | Role |
|---|---|---|
| [highlight.js](https://github.com/highlightjs/highlight.js) 11.12.0 | BSD 3-Clause | Syntax highlighting in the Functions tab's source viewer. Self-hosted (not loaded from a CDN) so the web UI keeps working on an offline/air-gapped network; see `web/vendor/hljs/LICENSE`. |

## Services (not bundled)

Optional LLM enrichment and the AI Assistant call the APIs of Anthropic (Claude), OpenAI, DeepSeek, or a local
[Ollama](https://ollama.com/) server. Their terms apply to the keys you supply.
