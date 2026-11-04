# Malimite-Core — Development Phases

> Last updated: 2026-11-05 — reflects actual codebase state, not the original planning baseline. Revised 2026-11-02: `report.html` rewritten as a formal bilingual VA document, CLI log timestamps, and a Claude thinking-response fix. Revised 2026-11-03: Auto Enhance (bulk AI Fix as a background job). Revised 2026-11-05 (Phase 5h — see below): fixed a correctness bug where `findings.sarif`/`--fail-on` never saw VulnerabilityScanner's rule-catalog findings at all (only LLM findings); built `tools/malimite-ci` + Bitbucket/Jenkins templates so an organization's own mobile-app CI/CD can trigger a scan against a running `malimite-web` server; added scan concurrency/rate limits and built-in retention (previously neither existed); fixed `deploy/Dockerfile`'s Ghidra version and wired up `publish-docker.yml` so the standalone image path actually publishes something; added an EC2 native-deployment guide.

## Current State (Baseline)

| Layer | Status |
|---|---|
| **Core analysis engine** (`core/`) | ✅ Production — Ghidra (iOS Mach-O + Android arm64 `.so`), JADX (Android DEX), MASTG/MSTG scanners, Assessment, LLM, SARIF/HTML |
| CLI (`cli/`) | ✅ Production — fat JAR with `--llm` (incl. `claude-oauth`), `--sarif`, `--html`, `--assessment`, `--fail-on`, `--ios-light`, `--decompiler asc`, `claude-login` subcommand; IPA + APK |
| Web UI + REST (`web/`) | ✅ Production — FastAPI + SPA; IPA/APK upload; Assessment tab; Functions Explorer (file tree + source viewer); unique vuln counts by `rule_id`; Triage + AI Fix overrides; Auto Enhance (bulk AI Fix background job) |
| Slack bot (`bot/python/`) | ⚠️ Works, not hardened — Socket Mode; `.ipa` / `.apk`; runs the CLI itself. No user allowlist, no concurrency cap, no tests; counts raw occurrences (not unique issues); no `JADX_HOME`/ASC settings; no `claude-oauth` mentioned in its own README. See *Chat bots* below |
| Watcher (`watcher/`) | ✅ Complete — inotify drop-folder daemon (`.ipa` / `.apk`) |
| Docker: web image (`deploy/web.Dockerfile`) | ✅ Ghidra 12.0.4 + font libs + JADX; runs as uid 10001; port bound to `127.0.0.1` by default. Full iOS scan verified end to end |
| Docker: standalone CLI image (`deploy/Dockerfile`) | ✅ Fixed (Phase 5h) — was still Ghidra 11.1.2 (rejected the scan's headless args: `Bad argument: -enableAnalyzer`); now 12.0.4 + JADX + font libs, same versions as `web.Dockerfile`. Published to GHCR on every version tag by `.github/workflows/publish-docker.yml` (didn't exist before — no workflow ever built/pushed this image). Built + scanned a real APK successfully in a real `docker build`/`docker run` during development |
| `tools/malimite-ci` | ✅ New (Phase 5h) — zero-dependency Python client for CI/CD pipelines (Bitbucket Pipelines, Jenkins, GitHub Actions): upload → poll → fetch `/vulnerabilities` → gate the build on severity. Computes its own severity gate rather than trusting the API's `exit_code` (process success/failure only, not a severity policy) or the CLI's `--fail-on` (not forwarded by the web service). Auto-detects CI provenance (pipeline URL/commit/triggered-by) from well-known env vars; tags the scan via new optional `ci_pipeline_url`/`ci_commit_sha`/`ci_triggered_by` fields on `ScanMeta` |
| AI Assistant (`web/app/agent/`) | ✅ Merged to `main` (PR #1). Tools: scan data, assessments, manifest, `recommend_hook_targets` (Frida), on-demand ASC/JADX/Ghidra. Verified with DeepSeek; Claude/OpenAI parsers only against recorded/fake streams. `claude-oauth` provider added (PR #5) |
| AI Fix (`web/app/finding_fix.py` + `web/app/main.py`) | ✅ Merged to `main`. Per-finding LLM rewrite of Description/Evidence/Risk/PoC/Remediation stored as reversible `Override*` columns; never touches original scanned text; revert endpoint restores it. Shares the AI Assistant's rate limit and LLM provider resolution |
| Auto Enhance (`web/app/auto_enhance.py` + `web/app/main.py`) | ✅ Merged to `main`. Bulk AI Fix as a server-side background job over many findings at once (reuses `finding_fix.fix_finding` per finding); live progress, Cancel Batch, per-finding Retry, Activity Log persisted per scan. One job per scan at a time; counts once against the shared rate limit regardless of finding count |
| GitHub / GitLab / Bitbucket CI / Jenkins | ✅ Two distinct paths, both working — see Phase 5h: (1) **recommended** — `tools/malimite-ci` + Bitbucket/Jenkins templates against a running `malimite-web` server; (2) standalone Docker image (GitHub Actions/GitLab templates), now actually publishing an image that works (was previously referencing a nonexistent GHCR package) |
| Legacy Javalin API (`api/`) | ⚠️ Legacy — superseded by `web/`; kept for Docker-compose compat |
| Legacy Worker / Java bots (Telegram, Discord, Slack-Java) | ⚠️ Legacy — upload to `POST /api/v1/scans` (compatible with the Python web API) and reply with the `scan_id` only: no results, no polling, no tests |
| Observability (Phase 6) | ❌ Not started |
| Security hardening (Phase 7) | ⚠️ Started — see Phase 7. Scan upload rate limiting and concurrency guard added (Phase 5h); previously neither existed |
| Enterprise scale (Phase 8) | ⚠️ Started — see Phase 8. Result retention policy (8.6) added (Phase 5h); previously none existed |

Unit tests: `core`/`cli` (262, 2 pre-existing environment-dependent `AscRunnerTest` failures unrelated to any feature — the test assumes a `droidasc` binary doesn't exist, which no longer holds once it's installed on PATH) cover IPA/APK validation, Android ingest, Assessment, catalogs, LLM providers (incl. Claude OAuth and the thinking-response regression), SARIF/HTML (incl. triage and AI Fix overrides, the VA report's JSON data contract, a JSON-escaping regression, and the `--fail-on`/SARIF rule-scanner-findings fix), learned-rule quality gates, on-demand decompilation, and the exit-code severity gate; `web/tests/` (214, stdlib `unittest`/`pytest`-compatible) cover the AI Assistant, Functions tab routes, triage, AI Fix, Auto Enhance (job runner concurrency/cancel/retry, routes), scan concurrency/rate limiting, and built-in retention; `tools/malimite-ci/test_malimite_ci.py` (31, stdlib-only `unittest`) covers the severity gate, the upload/poll/fetch HTTP flow, and CI metadata auto-detection. All three suites run on every pull request and on `main` (`.github/workflows/ci.yml`: Java on JDK 17 and 21, Python on 3.12, plus a dedicated `malimite-ci-client` job). **A real-IPA/APK scan does not run on CI yet** (it needs Ghidra / JADX on the runner) — `publish-docker.yml`'s smoke test only checks `malimite --version`, not an actual scan.

---

## Phase 1 — Core Engine (MVP)
**Status: ✅ ~95% — one gap remaining**

**Goal:** Real end-to-end IPA analysis — `MalimiteAnalyzer.analyze()` produces actual results.

### Tasks
| # | Task | Status | Notes |
|---|---|---|---|
| 1.1 | `IpaExtractor` | ✅ | NIO Zip extraction, no Swing |
| 1.2 | `InfoPlist` | ✅ | dd-plist based |
| 1.3 | `Macho` | ✅ | Universal binary slice extraction |
| 1.4 | `GhidraRunner` | ✅ | Headless `analyzeHeadless` + socket IPC; dynamic port; watchdog |
| 1.5 | Ghidra script | ✅ | `core/src/main/resources/ghidra/DumpClassData.java` |
| 1.6 | `CoreConfig` | ✅ | Env vars / system properties; no Swing |
| 1.7 | `MalimiteAnalyzer` | ✅ | Full pipeline wired; writes `scan.json` (was planned as `project.json`); IPA + APK |
| 1.8 | Integration test | ❌ | No test feeds a real `.ipa`/`.apk`; requires Ghidra ≥11.1 / JADX on CI |

### Deliverable
`java -jar malimite-cli.jar app.ipa --out /tmp/report` produces a populated SQLite DB and `scan.json`. **Met** — pending automated integration test.

### Dependencies
- Ghidra installation (≥11.1) on the build/test machine
- JADX (≥1.5) for Android APK DEX path
- dd-plist in core pom ✅

### Beyond original scope (done) — Android APK pipeline
| # | Task | Status | Notes |
|---|---|---|---|
| 1.A | `ApkValidator` / `ApkExtractor` | ✅ | APK structure checks + Zip extract |
| 1.B | `AndroidManifestParser` | ✅ | Package / permissions / components |
| 1.C | `JadxRunner` + `JadxIngest` | ✅ | DEX → Java; NSC / resource ingest |
| 1.D | Ghidra on `lib/arm64-v8a/*.so` | ✅ | Optional when `GHIDRA_HOME` set |
| 1.E | `AndroidVulnerabilityCatalog` | ✅ | MASTG Android static rules |
| 1.F | `PackagePlatform` routing | ✅ | iOS vs Android analyzer path |

---

## Phase 2 — Storage & Result API
**Status: ⚠️ ~90% — minor API gaps**

**Goal:** Analysis results queryable via REST; Worker returns real JSON findings.

### Tasks
| # | Task | Status | Notes |
|---|---|---|---|
| 2.1 | `SqliteStore` | ⚠️ | Schema + queries exist; **`getReferences()` not exposed** |
| 2.2 | `AnalysisReport` record | ✅ | Aggregates classes, functions, strings, metadata, vulns, assessments |
| 2.3 | JSON serialization | ✅ | Worker stores `AnalysisReport` JSON in `malimite:result:{scanId}` |
| 2.4 | `GET /api/v1/scans/{id}/result` | ⚠️ | ✅ Legacy Javalin API; **missing in Python `web/`** |
| 2.5 | Paginated functions endpoint | ✅ | Both Javalin API and Python web (`?class_name=&page=&size=`) |
| 2.6 | Summary endpoint | ⚠️ | ✅ Legacy Javalin API; **missing in Python `web/`** (UI builds from scan detail) |

### Deliverable
Full round-trip: upload IPA/APK → poll until done → fetch structured findings via REST. **Met on legacy stack; Python web needs `/result` + `/summary` parity.**

### Beyond original scope (done)
- `GET /api/v1/scans` list + `DELETE /api/v1/scans/{id}` on Python web ✅
- Vulnerability triage API (`PATCH .../vulnerabilities/{vuln_id}`) ✅
- `GET /api/v1/learned-rules` (platform-aware) ✅
- `GET /api/v1/scans/{id}/assessments` ✅
- Unique open-issue counting by `rule_id` (web + HTML) ✅

---

## Phase 3 — Code Analysis Depth
**Status: ⚠️ ~90% — cross-ref query gap**

**Goal:** Richer decompilation output — Swift demangling, cross-references, string classification.

### Tasks
| # | Task | Status | Notes |
|---|---|---|---|
| 3.1 | `DemangleSwift` | ✅ | Used in `GhidraRunner.ingestFunctions()` |
| 3.2 | `SyntaxParser` + ANTLR | ✅ | C++14 grammars in `core/src/main/antlr4/` |
| 3.3 | Cross-reference extraction | ⚠️ | Written to SQLite; **not queryable via REST or `getReferences()`** |
| 3.4 | String classification | ✅ | `ResourceParser` (plist/assets/…) + `MachoStrings` table |
| 3.5 | Entry-points detection | ⚠️ | Named lifecycle methods detected; **`@objc` entry points not yet detected** |
| 3.6 | `MobileProvision` | ✅ | Signing info in `scan.json` / `AnalysisReport` |

### Deliverable
Analysis output includes demangled Swift names, cross-reference graph, and classified string inventory. **Mostly met; cross-ref graph not yet exposed to consumers.**

---

## Phase 4 — LLM Integration
**Status: ⚠️ ~85% — async + cache wiring**

**Goal:** AI-powered method translation and vulnerability summarization.

### Tasks
| # | Task | Status | Notes |
|---|---|---|---|
| 4.1 | `LlmEnricher` + `LlmProvider` | ✅ | Platform-aware prompts (iOS / Android) |
| 4.2 | OpenAI provider | ✅ | GPT-4o / GPT-4o-mini via REST |
| 4.3 | Claude provider | ✅ | `claude-sonnet-4-6`; prompt caching on system prompt |
| 4.3b | **DeepSeek provider** | ✅ | `DeepSeekProvider`; models: `deepseek-v4-flash`, `deepseek-v4-pro`, `deepseek-chat`, `deepseek-reasoner` |
| 4.4 | Ollama provider | ✅ | `http://localhost:11434` default |
| 4.5 | Three enrichment modes | ✅ | `AUTO_FIX`, `SUMMARIZE`, `FIND_VULNS` |
| 4.6 | Async enrichment | ⚠️ | Runs **inline** in `MalimiteAnalyzer`; not a background job |
| 4.7 | LLM result cache | ⚠️ | `LlmCache` + `RedisLlmCache` in Worker; **CLI/analyzer uses `NOOP` cache** |

### Env vars
```
LLM_PROVIDER=openai|claude|deepseek|ollama|none
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
DEEPSEEK_API_KEY=
DEEPSEEK_BASE_URL=https://api.deepseek.com
OLLAMA_BASE_URL=http://localhost:11434
LLM_MODEL=        # override default model per provider
MALIMITE_LEARNED_RULES / MALIMITE_LEARNED_RULES_IOS   # iOS → ~/.malimite/learned_rules.json
MALIMITE_LEARNED_RULES_ANDROID                        # → ~/.malimite/learned_rules_android.json
```

### Deliverable
`--llm` flag in CLI and `llm_enabled: true` in API payload produce AI findings. **Met.**

### Beyond original scope (done)
- `LearnedRulesStore` — platform-scoped persistence; rejects hollow `...` / invalid regexes ✅
- `VulnerabilityScanner` + iOS MASTG/MSTG + Android catalogs ✅
- Self-validating regex before rule persistence ✅

---

## Phase 5 — CI/CD & Reporting
**Status: ✅ Complete**

**Goal:** Native integration into security pipelines; machine-readable and human-readable reports.

### Tasks
| # | Task | Status | Notes |
|---|---|---|---|
| 5.1 | SARIF 2.1 output | ✅ | `SarifExporter.java` → `findings.sarif` |
| 5.2 | GitHub Actions SARIF upload | ✅ | `upload-sarif@v3` active in `.github/workflows/ipa-scan.yml` |
| 5.3 | HTML report | ✅ | `HtmlReporter.java` — bilingual (ID/EN) formal VA document template (cover, risk rating, MASVS mapping, Assessment section, Android manifest summary, glossary, approval sheet), unique `rule_id` grouping; see Phase 5f |
| 5.4 | Exit code policy | ✅ | CLI `--fail-on=HIGH|MEDIUM|LOW` |
| 5.5 | GitLab CI template | ✅ | `.gitlab/malimite.yml` |
| 5.6 | Bitbucket Pipelines template | ✅ | `bitbucket-pipelines.yml` |
| 5.7 | Webhook notification | ✅ | Worker `WEBHOOK_URL` POST on completion |

### Deliverable
Running the CLI in CI produces SARIF uploaded to GitHub Security tab; failed builds on policy violations. **Met.**

---

## Phase 5b — Security Assessment
**Status: ✅ Complete**

**Goal:** Inventory implemented protections separately from vulnerability findings (not severity-counted as vulns).

### Tasks
| # | Task | Status | Notes |
|---|---|---|---|
| 5b.1 | `AssessmentScanner` + statuses | ✅ | `PRESENT` / `PARTIAL` / `ABSENT` / `UNKNOWN` |
| 5b.2 | CLI `--assessment` / `--no-assessment` | ✅ | Default: on |
| 5b.3 | Web checkbox + Assessment tab | ✅ | `GET /api/v1/scans/{id}/assessments` |
| 5b.4 | HTML *Security Controls Assessment* | ✅ | Separate from vuln severity totals |
| 5b.5 | Controls coverage | ✅ | Obfuscation, SSL pinning, root/jailbreak & Frida, FLAG_SECURE, native ELF hardening, … |

### Deliverable
Assessment results appear in CLI/HTML/web without mixing into vulnerability severity counts. **Met.**

---

## Phase 5c — AI Assistant
**Status: ✅ Merged to `main` (PR #1) — 5c.6–5c.9 still open**

**Goal:** Let an analyst talk to the scan: ask about code, findings and controls, and request reverse engineering of a class or function on demand.

| # | Task | Status | Notes |
|---|---|---|---|
| 5c.1 | Agent loop + streaming chat API | ✅ | `web/app/agent/`; SSE; Anthropic and OpenAI-compatible (openai, deepseek, ollama) clients; per-message tool-round limit with a forced final answer; answers cut off by the output limit continue automatically |
| 5c.2 | Tools over scan data | ✅ | `scan_overview`, `list_classes`, `search_code`, `get_source`, `search_strings`, `get_vulnerabilities` (grouped like the UI), `get_references`, `get_assessments`, `get_manifest` |
| 5c.3 | On-demand decompilation | ✅ | `OnDemandDecompiler`: ASC (≈0.2 s/class), JADX `--single-class` (≈8 s), Ghidra with a persistent project (iOS Mach-O first import ≈3.6 min, then ≈4.5 s). Verified with the real tools |
| 5c.4 | Chat UI | ✅ | "AI Assistant" tab, sessions kept per scan, markdown rendering, API-key aware |
| 5c.5 | Safety | ✅ | Read-only scan DB, tool output treated as untrusted data, validated targets, allowlisted subprocess environment, key only from server settings, global rate limit |
| 5c.6 | Regression set for answer quality | ❌ | Fixed questions against a sample scan asserting tool numbers (unique issues, severities) |
| 5c.7 | Verify Claude / OpenAI streams against the real APIs | ❌ | Only DeepSeek has been exercised with a real key |
| 5c.8 | Triage from chat ("mark false positive") | ❌ | Would be the first write tool: needs an explicit confirmation step |
| 5c.9 | Bots can forward questions to `/chat` | ❌ | See *Chat bots* |

---

## Phase 5d — Detection quality
**Status: ✅ First round done; needs a wider corpus**

**Goal:** Fewer false positives and no over-confident "absent" claims.

| # | Task | Status | Notes |
|---|---|---|---|
| 5d.1 | Quality gates for LLM-learned rules (`RuleQuality`) | ✅ | Semantic anchor, word boundaries, specificity vs the same app, scan-time guard (more than 20 functions → no findings), learned findings capped at MEDIUM; gates also filter stored rules |
| 5d.2 | Prune shipped seed rules | ✅ | 17 iOS and 1 Android removed; a test keeps `deploy/rules/` clean. On a real crackme: 24 → 5 occurrences |
| 5d.3 | Relevance preconditions for absence rules | ✅ | Pinning needs networking, keyboard rule needs a text input, GMS rule needs GMS |
| 5d.4 | Bytecode-VM detection (`ObfuscationSignals`) | ✅ | Detection controls that found nothing become `UNKNOWN`; resilience findings carry a caveat |
| 5d.5 | Validate the gates on more apps | ❌ | iOS validated on a single app (156 functions); no negative corpus of normal Ghidra output; the 69 remaining iOS seeds are unaudited beyond static checks |
| 5d.6 | Negative-test learned rules against a corpus before persisting | ❌ | Today only the app being scanned is used |

---

## Phase 5e — AI Fix
**Status: ✅ Complete**

**Goal:** Let a reviewer ask the LLM to rewrite one finding's report text (Description, Evidence, Risk, Proof of Concept, Remediation) without losing the original scanned data or re-running the scan.

| # | Task | Status | Notes |
|---|---|---|---|
| 5e.1 | Reversible override storage | ✅ | `SqliteStore`: 9 new `Vulnerabilities` columns (`OverrideDescription`/`Evidence`/`PocSteps`/`Remediation`, `AiFixStatus`/`Provider`/`Model`/`At`, `AiFixSeverityWasAi`). Risk reuses the existing triage `OverrideSeverity`/`OverrideCvssScore` columns; `AiFixSeverityWasAi` ensures a revert never clobbers a human's own manual triage override |
| 5e.2 | Report-layer effective values | ✅ | `AnalysisReport.VulnerabilityRecord.effectiveDescription()`/`effectiveEvidence()`/`effectivePocSteps()`/`effectiveRemediation()`/`isAiFixed()`, consumed by `HtmlReporter` and the Python `db.get_vulnerabilities()` (`SarifExporter` does not read the `Vulnerabilities` table, so it was left untouched) |
| 5e.3 | LLM call | ✅ | `web/app/finding_fix.py`: single-shot prompt + robust JSON extraction + sanitation, grounded in the finding and (for `FUNCTION` findings) its decompiled source; reuses `agent/llm.py`'s `resolve_llm`/`chat_step` — no new LLM client |
| 5e.4 | REST endpoints | ✅ | `POST /api/v1/scans/{id}/vulnerabilities/{vuln_id}/ai-fix` and `.../ai-fix/revert`; shares the AI Assistant's chat rate limit (`CHAT_RATE_PER_MIN`) |
| 5e.5 | Web UI | ✅ | Per-finding ✨ AI Fix panel: field checkboxes (Description/Evidence/Risk/PoC/Remediation), provider+model dropdown (same `LLM_MODEL_CATALOG` as the upload form and AI Assistant), "AI-enhanced" badge, Revert to original |
| 5e.6 | Tests | ✅ | `SqliteStoreAiFixTest`, an `HtmlReporterTest` case, `test_ai_fix_route.py` (endpoint + unit tests for the JSON extractor) |

### Deliverable
A reviewer clicks ✨ AI Fix on a finding, picks a provider/model and which fields to rewrite, and the LLM-generated text appears in the live Vulnerabilities tab and `report.html` with a visible provenance note — fully reversible. **Met.**

---

## Phase 5f — VA Report Overhaul & Scan Reliability
**Status: ✅ Complete**

**Goal:** Replace `report.html`'s compact technical-dashboard layout with a formal, bilingual (ID/EN) Vulnerability Assessment document suitable for a client deliverable, and fix two scan-reliability issues found while investigating it.

| # | Task | Status | Notes |
|---|---|---|---|
| 5f.1 | VA report templates | ✅ | `core/src/main/resources/report-template/va-report-{ios,android}.html` — self-contained HTML+JS, not Java string-building: a single `<script type="application/json">` data block renders cover page, executive summary, risk rating scale, findings (grouped by `rule_id`), MASVS mapping, Security Assessment, Android manifest summary, glossary, and an approval sheet, with an ID/EN language toggle. Logo inlined as SVG in the cover (no separate asset, keeps the report portable) |
| 5f.2 | `HtmlReporter.java` rewrite | ✅ | From an HTML string-builder into a JSON serializer + template injector; picks the iOS/Android template by platform, maps `AnalysisReport` into the templates' documented data contract, keeps existing triage/AI-Fix effective-value and `rule_id`-grouping semantics. `TEMPLATE_VERSION` bumped 4→7 across this work's revisions (kept in sync with `web/app/main.py`) so every on-disk `report.html` auto-regenerates via the existing `ReportRenderer` staleness check |
| 5f.3 | Android manifest data | ✅ | `AnalysisReport.AndroidManifestInfo` (`debuggable`/`allowBackup`/`usesCleartextTraffic`/`networkSecurityConfig`/`permissions`/`components`) — `AndroidManifestParser` already extracted these but they weren't threaded through to the report; now saved in `scan.json` (`MalimiteAnalyzer`) and read back (`ReportBuilder`) |
| 5f.4 | Print/PDF color fix | ✅ | `print-color-adjust:exact` in both templates' `@media print` — without it, "Save as PDF" silently drops `background-color` from everything but `<body>`/links, so the MASVS-category bar chart, severity/status badges, and the risk-posture box rendered colorless in print even though they look correct on screen |
| 5f.5 | JSON-escaping bug fix | ✅ | The template-data injector wrapped `String.replace(CharSequence,CharSequence)` in `Matcher.quoteReplacement()`, which is meaningless outside `replaceAll`/`replaceFirst`'s regex-replacement syntax — it silently doubled every backslash already in the serialized JSON. A Mach-O string containing a literal quote (`"/usr/lib/dyld"`, quotes included) corrupted the embedded JSON enough to throw a `SyntaxError` in the browser's own `JSON.parse`. Fixed with plain `replace()`; two regression tests added |
| 5f.6 | CLI log timestamps | ✅ | `cli/src/main/resources/simplelogger.properties` — every log line now gets an `HH:mm:ss.SSS` prefix; slf4j-simple previously ran on its bare default (no timestamp), making it impossible to tell how long a step took from `analysis.log` / the web UI's Log tab |
| 5f.7 | Claude thinking-response fix | ✅ | `ClaudeOAuthProvider`/`ClaudeProvider`: Claude 5+ models run extended thinking by default (no `thinking` request param needed) and its tokens count against the same `max_tokens` as the visible answer — on scan enrichment's 4096 default, a model could spend the whole budget thinking and return no `text` block at all. Both providers now send `thinking:{"type":"disabled"}`, retrying once without it if a model family rejects that value (HTTP 400); `extractText()` scans for the first `text` block instead of assuming index 0 |
| 5f.8 | Tests | ✅ | `HtmlReporterTest` rewritten to parse the injected JSON back out of the generated HTML and assert against it directly (18→20 tests); `ClaudeOAuthProviderTest` (8 new); `SimpleLoggerConfigTest` (1 new) |

### Deliverable
`report.html` is a document a reviewer can hand to a client as-is (after filling in the `—` administrative placeholders): cover, executive summary, risk scale, findings, MASVS mapping, glossary, approval sheet, print-to-PDF with correct colors. Verified end to end against real iOS and Android scans in-browser with zero console errors. **Met.**

---

## Phase 5g — Auto Enhance
**Status: ✅ Complete**

**Goal:** Let a reviewer run AI Fix across many findings at once instead of clicking it one finding at a time, without blocking the browser and without a report regeneration per finding.

| # | Task | Status | Notes |
|---|---|---|---|
| 5g.1 | Shared per-finding apply | ✅ | `web/app/auto_enhance.py`'s `apply_ai_fix_to_row()` extracted from the per-finding AI Fix endpoint's body so both the single-finding route and the bulk job call the exact same LLM-call + reversible-override-write logic; the per-finding route itself is otherwise unchanged (same 18 existing tests still pass) |
| 5g.2 | Background job runner | ✅ | In-process job registry (`_JOBS`/`_RUNTIME`, keyed by a short job id) with bounded concurrency (`asyncio.Semaphore`, default 2, `AUTO_ENHANCE_CONCURRENCY`); the report is regenerated **once** after the whole batch, not once per finding. One active job per scan (`_ACTIVE_BY_SCAN`) — a second start attempt gets `409` |
| 5g.3 | Per-item detail | ✅ | Each item tracks state (`pending`/`running`/`applied`/`failed`/`cancelled`), duration, attempt count, which fields the LLM actually rewrote, and the rewritten text itself (`_changes_from_fix`, clipped to 2000 chars) — enough for the UI's View Details panel without re-reading the database |
| 5g.4 | Cancel Batch | ✅ | `request_cancel()` sets a flag items check right before they start their LLM call: findings already mid-call finish normally (nothing half-written), everything still queued is marked `cancelled` and skipped — no abrupt task cancellation |
| 5g.5 | Retry Finding | ✅ | `retry_item()` re-runs one `failed`/`cancelled` item with the run's original provider/model/fields, inside the *same* job/Activity Log entry (not a new run) — queues into a still-running job, or transparently reopens a finished one and regenerates the report again if the retry succeeds. Refused (`409`) while a cancel is in progress, so a retry can't un-cancel a batch mid-stop |
| 5g.6 | Activity Log persistence | ✅ | Every finished run appended to `<scan_dir>/auto_enhance_log.json` (capped at 50 entries), survives a server restart; `GET .../auto-enhance` returns the active job (if any) plus history so reopening the modal — even from a different browser tab — picks the live run back up |
| 5g.7 | REST endpoints | ✅ | `POST /api/v1/scans/{id}/auto-enhance` (202, starts a job), `GET .../auto-enhance` (overview), `GET .../auto-enhance/jobs/{job_id}` (poll, falls back to the persisted log after a restart), `POST .../jobs/{job_id}/cancel`, `POST .../jobs/{job_id}/items/{vuln_id}/retry`. One `_chat_rate_limit()` hit per **run**, not per finding |
| 5g.8 | Web UI | ✅ | "✨ Auto Enhance" button on the Vulnerabilities tab opens a modal: provider/model pickers, a searchable/filterable findings table with Select all/Clear, a Fields-to-enhance picker, and an **Activity Log** tab with a progress ring, elapsed-time clock, per-finding timeline, Cancel Batch, Retry Finding, View Details, and View Full Log across runs |
| 5g.9 | Tests | ✅ | `test_auto_enhance.py` (21 new: job runner concurrency/cancel/retry/persistence, all 7 route cases) |

### Deliverable
A reviewer selects any number of findings, picks which fields to rewrite, and clicks Run Auto Enhance; the batch runs on the server with live progress, can be cancelled mid-run without losing in-flight work, and any failure can be retried individually without re-running the whole batch. Verified end to end in-browser against a real scan (`dvba_v1.1.0.apk`) with DeepSeek: a 4-finding run, a mid-run cancel (2 completed / 2 skipped), a successful retry of a skipped finding, and a deliberately-invalid-model run to exercise the failed/error path. **Met.**

---

## Phase 5h — Organizational CI/CD Integration

**Status: ✅ Complete**

**Goal:** Let an organization's own mobile-app repositories trigger a Malimite scan automatically on every build/release (Bitbucket Pipelines, Jenkins), with results reviewable in the web UI afterward — and fix the correctness/operational gaps that surfaced while building toward that.

| # | Task | Status | Notes |
|---|---|---|---|
| 5h.1 | `--fail-on`/SARIF rule-scanner bug fix | ✅ | `SarifExporter` never wrote `VulnerabilityScanner`'s MASTG/MSTG rule-catalog findings to `findings.sarif` at all — only entry points, a hardcoded-string regex, and optional LLM findings. `Main.computeExitCode()` had the same blind spot (`--fail-on` only checked `llmFindings()`), so a scan run without `--llm` — the common case — could never trip `--fail-on` regardless of severity. Reproduced directly: `dvba_v1.1.0.apk` without `--llm` found 51 findings incl. 7 HIGH, yet `findings.sarif` had 0 rule-scanner results and `--fail-on HIGH` exited 0. Fixed: new `MALIMITE004` SARIF rule exports `report.vulnerabilities()` via `effectiveSeverity()` (honors triage/AI-Fix overrides), skipping suppressed (`false_positive`/`fixed`) findings; `computeExitCode()` now considers both finding sources |
| 5h.2 | `tools/malimite-ci` | ✅ | Zero-dependency (stdlib `urllib`) Python client: upload → poll → fetch `/vulnerabilities` → compute its own severity gate (deliberately not trusting the API's `exit_code` or the CLI's `--fail-on`, neither of which reflects a severity policy over this path). Auto-detects CI provenance (pipeline URL/commit SHA/triggered-by) from Bitbucket/Jenkins/GitHub Actions env vars, overridable via `--ci-*` flags. 31 tests, `urlopen` mocked |
| 5h.3 | CI scan provenance | ✅ | New optional `ci_pipeline_url`/`ci_commit_sha`/`ci_triggered_by` on `ScanMeta`/`ScanDetail`, set via `POST /api/v1/scans` form fields — backward compatible (default `None`). Data-layer only; no web UI badge yet distinguishing CI-triggered scans from manual uploads |
| 5h.4 | Bitbucket Pipelines + Jenkins templates | ✅ | Rewrote `bitbucket-pipelines.yml` (previously assumed a `docker run ghcr.io/malimite/malimite:latest` image that never existed) and added a new `Jenkinsfile` — both call `tools/malimite-ci` against a running `malimite-web` server. Both are copy-paste references for a mobile-app repo's own pipeline, not something that runs inside Malimite-Core itself |
| 5h.5 | Scan concurrency guard | ✅ | `scanner.create_scan()`/`_run()` previously had no limit at all — every upload spawned its own Ghidra/JADX subprocess immediately. New `max_concurrent_scans` (default 3, `asyncio.Semaphore`, same per-event-loop pattern as `heavy_concurrency`); a scan blocked behind the limit stays `queued` (not misleadingly `running`) until a slot frees. Verified against the live sandbox server: 4 parallel uploads showed exactly 3 `running` + 1 `queued` |
| 5h.6 | Scan upload rate limiting | ✅ | New `scan_rate_per_min` (default 30, sliding-window `deque`, same pattern as the existing `_chat_rate_limit()`) — separate from `chat_rate_per_min`, which only guards LLM spend, not raw scan starts. Raises `429` with `Retry-After` |
| 5h.7 | Built-in scan retention | ✅ | Phase 8.6 gap closed. New `scan_retention_days` (default `0` = disabled, preserving prior "keep everything" behavior). `delete_expired_scans()` ages from `created_at`, skips `queued`/`running` scans regardless of age, tolerates missing/corrupt `meta.json`. Runs once at startup, then on a daily background task started/cancelled cleanly in `main.py`'s `lifespan` |
| 5h.8 | `deploy/Dockerfile` fix + GHCR publish | ✅ | Was still Ghidra 11.1.2 (same `-enableAnalyzer` rejection as above); bumped to 12.0.4, added the font libs `web.Dockerfile` already had, base image JDK 17→21 (JDK 22 breaks Ghidra's OSGi loader). New `.github/workflows/publish-docker.yml` builds+smoke-tests+pushes to `ghcr.io/<owner>/malimite` on every version tag — no workflow ever did this before, so `ipa-scan.yml`/`.gitlab/malimite.yml` referenced a nonexistent image. Built and scanned a real APK inside the fixed image with `docker build`/`docker run` during development (not just in CI) |
| 5h.9 | EC2 native deployment guide | ✅ | New `deploy/EC2_DEPLOYMENT.md` — native systemd (matches the already-verified dev setup, not `deploy/web.Dockerfile`, which has never been deployment-tested outside a sandbox): instance sizing (explicit callout that scans have no server-side queue, so size for RAM headroom), security group placement, exact pinned Ghidra/JADX versions, separate EBS volume for scan data, the new built-in retention setting, the systemd unit, mandatory `API_KEY`, and an end-to-end smoke test |
| 5h.10 | Tests | ✅ | 9 new `SarifExporterTest` + 15 new `MainTest` (Java); 5 new `test_upload_formats.py` + 7 new `test_scanner_concurrency.py` + 13 new `test_scanner_retention.py` (Python web); 31 new `tools/malimite-ci/test_malimite_ci.py` |

### Deliverable
An organization's Bitbucket Pipelines or Jenkins build calls `tools/malimite-ci` against a `malimite-web` server (deployable to EC2 per the new guide); the pipeline fails on a severity threshold computed from real findings (not a previously-broken gate); the server survives a burst of concurrent CI-triggered scans without unbounded subprocess spawn; old scans age out automatically instead of filling disk forever; and the exact same scan is visible in the web UI for manual review (triage, AI Fix, Auto Enhance, report.html) since CI-triggered and manually-uploaded scans share the same `POST /api/v1/scans` code path with no separate registry. **Met** — verified with real scans against both the live sandbox server and a real `docker build`/`docker run` of the fixed standalone image, not just unit tests.

---

## Phase 6 — Observability
**Status: ❌ Not started — NEXT MAJOR PHASE**

**Goal:** Production visibility: metrics, structured logs, enriched health checks.

### Tasks
| # | Task | Status | Notes |
|---|---|---|---|
| 6.1 | Prometheus metrics | ❌ | No Micrometer dep; no `/metrics` endpoint |
| 6.2 | Structured logging | ❌ | `slf4j-simple` only; no JSON encoder; no `scan_id` MDC |
| 6.3 | Enriched health check | ❌ | `GET /healthz` returns `"ok"` only — no Redis/MinIO/Ghidra/JADX checks |
| 6.4 | Queue depth metric | ❌ | |
| 6.5 | Grafana dashboard | ❌ | No `deploy/grafana/` |
| 6.6 | Alert rules | ❌ | No `deploy/prometheus/alerts.yml` |

### New env vars
```
METRICS_ENABLED=true
```

### Deliverable
Grafana dashboard showing live scan throughput, queue depth, and error rate. Alerts fire on anomalies.

---

## Phase 7 — Security & Hardening
**Status: ⚠️ Started (~30%)**

**Goal:** Production security — protect the analysis service from abuse.

### Tasks
| # | Task | Status | Notes |
|---|---|---|---|
| 7.1 | JWT / API key scopes | ⚠️ | Single `API_KEY`, compared in constant time; the UI remembers it and fetches downloads with it. No scopes |
| 7.2 | Rate limiting | ⚠️ | Global cap on chat requests (`CHAT_RATE_PER_MIN`). Scan uploads now also bounded (Phase 5h): `SCAN_RATE_PER_MIN` (raw scan starts) + `MAX_CONCURRENT_SCANS` (concurrent Ghidra/JADX subprocesses, previously unbounded). Not yet per-user/per-key — both are global server-wide limits |
| 7.3 | Zip bomb / path traversal guard | ❌ | `IpaValidator` / `ApkValidator` check size + structure; no compression-ratio guard |
| 7.4 | Sandbox Ghidra / JADX process | ⚠️ | Web image runs as uid 10001; decompiler subprocesses get an allowlisted environment (no LLM/API keys) and die with their process group. No seccomp, no network isolation |
| 7.5 | Secrets management | ⚠️ | Per-upload LLM key is no longer written to `meta.json` (old ones scrubbed at start); LLM keys only from server settings. No Vault/SSM, no log masking |
| 7.6 | Audit log | ❌ | |
| 7.7 | TLS termination | ❌ | |
| 7.8 | Safe defaults | ✅ | Compose publishes `127.0.0.1` only (`MALIMITE_BIND`), `run.sh` binds loopback, startup warning when `API_KEY` is empty |
| 7.9 | Access control for chat bots | ❌ | Any member of a channel the bot is in can start a heavy scan |

### Deliverable
Penetration-test ready deployment; scoped API keys; decompilers run in restricted sandbox.

---

## Phase 8 — Scale & Enterprise
**Status: ❌ Not started**

**Goal:** Kubernetes-native, multi-tenant, enterprise auth.

### Tasks
| # | Task | Status | Notes |
|---|---|---|---|
| 8.1 | PostgreSQL store | ❌ | Only `SqliteStore` |
| 8.2 | Helm chart | ❌ | No `deploy/helm/malimite/` |
| 8.3 | Horizontal Pod Autoscaler | ❌ | docker-compose `replicas: 2` only |
| 8.4 | Multi-tenancy | ❌ | Single MinIO bucket / Redis namespace |
| 8.5 | OIDC / SSO | ❌ | |
| 8.6 | Result retention policy | ✅ | Done in Phase 5h. `SCAN_RETENTION_DAYS` (default `0` = disabled); `delete_expired_scans()` ages from `created_at`, skips `queued`/`running` scans, runs at startup then daily in the background |
| 8.7 | Web UI v2 | ❌ | Vanilla JS SPA in `web/index.html`; no React app |

### Deliverable
Deployable to GKE/EKS/AKS via Helm; auto-scales workers on demand; enterprise SSO.

---

## Phase Summary

```
Phase 1   █████████░  Core Engine (+ Android) ~95%   [1.8 integration test remaining]
Phase 2   █████████░  Storage & Result API    ~90%   [/result + /summary on Python web]
Phase 3   █████████░  Analysis Depth          ~90%   [cross-ref query API]
Phase 4   ████████░░  LLM Integration         ~85%   [async job + Redis cache in analyzer]
Phase 5   ██████████  CI/CD & Reporting       100%   ✅ DONE [see Phase 5h for a correctness fix + real org-CI/CD integration]
Phase 5b  ██████████  Security Assessment     100%   ✅ DONE
Phase 5c  █████████░  AI Assistant            ~90%   [merged in PR #1; hook-target + claude-oauth added; 5c.6–5c.9 open]
Phase 5d  ███████░░░  Detection quality       ~70%   [wider corpus needed]
Phase 5e  ██████████  AI Fix                  100%   ✅ DONE
Phase 5f  ██████████  VA Report Overhaul      100%   ✅ DONE
Phase 5g  ██████████  Auto Enhance            100%   ✅ DONE
Phase 5h  ██████████  Org CI/CD Integration   100%   ✅ DONE [malimite-ci, Bitbucket/Jenkins templates, concurrency/retention, fail-on/SARIF bug fix]
Phase 6   ░░░░░░░░░░  Observability             0%   ← NEXT MAJOR PHASE
Phase 7   ████░░░░░░  Security & Hardening     ~40%   [started: 7.1, 7.2, 7.4, 7.5, 7.8 partial; scan rate-limit/concurrency new in 5h]
Phase 8   █░░░░░░░░░  Scale & Enterprise       ~10%   [8.6 result retention done in 5h; 8.1–8.5, 8.7 not started]
```

### Chat bots (Slack / Telegram / Discord)
Readiness today: the **standalone Python Slack bot** works end to end (it runs the CLI and replies in a thread with a
summary, HTML report and SARIF); the **Java Telegram/Discord/Slack bots** only queue a scan and reply with its id. Both
need work before they are production-ready:
1. One backend: make every bot talk to the Python web API (`POST /api/v1/scans`, poll, fetch the summary) instead of
   running the CLI itself or relying on the legacy API.
2. Report what the UI reports: unique issues per `rule_id` plus occurrences, Assessment highlights, a link to the scan.
3. Access control and limits: user/channel allowlist, a concurrency cap, per-user rate limit, file-size limits.
4. APK settings (`JADX_HOME`, `ASC_HOME`) in the bot configuration; tests for message formatting and the upload flow.
5. Privacy: uploading an app to a chat service and posting the report back sends it to a third party. Document it and
   let operators restrict where reports are posted.
6. Update the legacy Docker image to Ghidra 12.0.4 or retire it in favour of the web image.

**Critical path (closure):** Finish Phase 1.8 → Phase 2 gaps → Phase 3 cross-ref API (~1 week total).
**Next major phase:** Phase 6 Observability (can start in parallel with closure work).
Phases 7–8 depend on Phase 6 being in place for production deployments.

---

## Recommended Next Steps

### 1. Close out Phases 1–4 (≈1 week) — do this first

| Priority | Task | Phase | Effort |
|---|---|---|---|
| P0 | Real-IPA/APK integration test (Ghidra/JADX on CI or `@EnabledIfEnvironmentVariable`) | 1.8 | ~1 day |
| P1 | `SqliteStore.getReferences()` + `GET .../references` on Python web | 2.1 / 3.3 | ~4h |
| P1 | Add `GET /api/v1/scans/{id}/result` and `/summary` to `web/app/main.py` | 2.4 / 2.6 | ~2h |
| P2 | Wire `RedisLlmCache` into `MalimiteAnalyzer` (not just Worker) | 4.7 | ~4h |
| P2 | Background LLM enrichment job (decouple from scan critical path) | 4.6 | ~1 day |

### 2. Phase 6 — Observability (≈1–2 weeks) — next major milestone

Start with enriched `/healthz` (Redis + Ghidra/JADX path checks) and Prometheus `/metrics` on the Python web service, then Grafana dashboard + alert rules.

### 3. Phase 7 — Security (≈2 weeks) — before public-facing production

Priority: zip-bomb guard in validators (7.3) and rate limiting (7.2) before JWT scopes (7.1).

---

## Quick Wins

| Task | Module | Status | Effort |
|---|---|---|---|
| Add `/api/v1/scans` list endpoint | api / web | ✅ Done (Python web) | — |
| Add scan cancellation `DELETE /api/v1/scans/{id}` | api / web | ✅ Done (Python web) | — |
| Android APK + JADX pipeline | core / cli / web | ✅ Done | — |
| Security Assessment mode | core / cli / web | ✅ Done | — |
| Unique vuln counts by `rule_id` | web / HtmlReporter | ✅ Done | — |
| Platform-scoped learned rules | core / web | ✅ Done | — |
| Bot: reply with progress updates during polling | bot/python | ❌ Open | ~4h |
| GitHub Actions: matrix scan (multiple IPAs/APKs) | `.github/` | ❌ Open | ~2h |
| Add `Content-Security-Policy` headers to web UI | web | ❌ Open | ~1h |
| Update stale `core/README.md` checklist | core | ✅ Done | — |
| `@objc` entry-point detection in `GhidraRunner` | core | ❌ Open | ~4h |

---

## Extras Implemented (outside original phase plan)

| Feature | Module | Notes |
|---|---|---|
| iOS MASTG/MSTG vulnerability scanner | `core/` | `VulnerabilityScanner` + `VulnerabilityCatalog` |
| Android MASTG vulnerability scanner | `core/` | `AndroidVulnerabilityCatalog` + JADX ingest |
| Android APK pipeline | `core/` | Validate/extract/manifest/JADX; optional Ghidra on arm64 `.so` |
| Security Assessment mode | `core/` + `web/` + CLI | PRESENT/PARTIAL/ABSENT/UNKNOWN; not mixed into vuln severity |
| Platform-aware LLM + learned rules | `core/` | `learned_rules.json` / `learned_rules_android.json`; hollow `...` rejected |
| Unique vulnerability counting | `web/` + `HtmlReporter` | Grouped by `rule_id` |
| Vulnerability triage workflow | `core/` + `web/` | Status, severity override, CVSS override, reviewer notes |
| AI Fix | `core/` + `web/` | Per-finding LLM rewrite of Description/Evidence/Risk/PoC/Remediation, reversible overrides, see Phase 5e |
| Functions Explorer | `web/` | JADX-GUI-style file tree + source viewer + outline + on-demand decompile for the Functions tab |
| iOS light scan mode (`--ios-light`) | `core/` + `cli/` | Skips Ghidra, scans strings/symbols/plist only; for binaries too large for Ghidra auto-analysis |
| Claude Pro/Max OAuth LLM provider (`claude-oauth`) | `core/` + `cli/` + `web/` | `malimite claude-login` subcommand (interactive PKCE, `--import`, or pasted tokens); no separately-billed `ANTHROPIC_API_KEY` |
| Claude/DeepSeek model catalog refresh | `web/` + `core/` | Default Claude model is now Sonnet 5 (was 4.6); DeepSeek's official Flash id is now `deepseek-flash` (was `deepseek-v4-flash`, still accepted) |
| Python Slack bot (Socket Mode) | `bot/python/` | Supersedes Java bot module; IPA + APK |
| FastAPI web service | `web/` | Primary deployment; runs CLI as subprocess |
