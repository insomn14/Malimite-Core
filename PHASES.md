# Malimite-Core — Development Phases

> Last updated: 2026-08-10 — reflects actual codebase state, not the original planning baseline.

## Current State (Baseline)

| Layer | Status |
|---|---|
| **Core analysis engine** (`core/`) | ✅ Production — Ghidra (iOS Mach-O + Android arm64 `.so`), JADX (Android DEX), MASTG/MSTG scanners, Assessment, LLM, SARIF/HTML |
| CLI (`cli/`) | ✅ Production — fat JAR with `--llm`, `--sarif`, `--html`, `--assessment`, `--fail-on`; IPA + APK |
| Web UI + REST (`web/`) | ✅ Production — FastAPI + SPA; IPA/APK upload; Assessment tab; unique vuln counts by `rule_id` |
| Slack bot (`bot/python/`) | ✅ Production — Socket Mode; `.ipa` / `.apk` |
| Watcher (`watcher/`) | ✅ Complete — inotify drop-folder daemon (`.ipa` / `.apk`) |
| Docker / Compose (`deploy/`) | ✅ Complete — Ghidra + JADX image; Redis + MinIO + api/worker/watcher stack |
| GitHub / GitLab / Bitbucket CI | ✅ Complete — SARIF upload wired (stock templates are IPA-oriented; image includes JADX) |
| Legacy Javalin API (`api/`) | ⚠️ Legacy — superseded by `web/`; kept for Docker-compose compat |
| Legacy Worker / Java bots | ⚠️ Legacy — Redis queue path; Python web runs CLI in-process |
| Observability (Phase 6) | ❌ Not started |
| Security hardening (Phase 7) | ❌ Not started |
| Enterprise scale (Phase 8) | ❌ Not started |

Unit tests in `core/` cover IPA/APK validation, Android ingest, Assessment, catalogs, LLM, SARIF/HTML, and platform-scoped learned rules. No real-IPA/APK integration test on CI yet (requires Ghidra / JADX on the runner).

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
| 5.3 | HTML report | ✅ | `HtmlReporter.java` — vuln-centric layout + Assessment section + unique `rule_id` grouping |
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
**Status: ❌ Not started**

**Goal:** Production security — protect the analysis service from abuse.

### Tasks
| # | Task | Status | Notes |
|---|---|---|---|
| 7.1 | JWT / API key scopes | ❌ | Single optional `API_KEY` / `MALIMITE_API_KEY` only |
| 7.2 | Rate limiting | ❌ | No Redis sliding-window filter |
| 7.3 | Zip bomb / path traversal guard | ❌ | `IpaValidator` / `ApkValidator` check size + structure; no compression-ratio guard |
| 7.4 | Sandbox Ghidra / JADX process | ❌ | No dedicated OS user; no seccomp in Docker |
| 7.5 | Secrets management | ❌ | No Vault/SSM; no log token masking |
| 7.6 | Audit log | ❌ | No `malimite:audit` Redis list |
| 7.7 | TLS termination | ❌ | No nginx sidecar or `deploy/nginx.conf` |

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
| 8.6 | Result retention policy | ❌ | |
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
Phase 5   ██████████  CI/CD & Reporting       100%   ✅ DONE
Phase 5b  ██████████  Security Assessment     100%   ✅ DONE
Phase 6   ░░░░░░░░░░  Observability             0%   ← NEXT MAJOR PHASE
Phase 7   ░░░░░░░░░░  Security & Hardening      0%
Phase 8   ░░░░░░░░░░  Scale & Enterprise        0%
```

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
| Update stale `core/README.md` checklist | core | ❌ Open | ~15m |
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
| Python Slack bot (Socket Mode) | `bot/python/` | Supersedes Java bot module; IPA + APK |
| FastAPI web service | `web/` | Primary deployment; runs CLI as subprocess |
