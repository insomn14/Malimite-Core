# Malimite-Core

**Headless iOS & Android static analysis platform** — decompile `.ipa` (Ghidra) and `.apk` (JADX for DEX, optional Ghidra for arm64 `.so`), scan against OWASP MASTG/MSTG rules, optionally enrich with LLM, and deliver findings through a web UI, REST API, Slack bot, or CI/CD pipeline.

> Inspired by and ported from [**Malimite**](https://github.com/LaurieWired/Malimite) by [@LaurieWired](https://github.com/LaurieWired) — the excellent interactive iOS/macOS decompiler. Malimite-Core takes the same Ghidra-backed analysis pipeline and refactors it for **automation, team workflows, and continuous security scanning** instead of desktop GUI use.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-17+-orange.svg)](https://openjdk.org/)
[![Ghidra](https://img.shields.io/badge/Ghidra-%E2%89%A511.1-purple.svg)](https://ghidra-sre.org/)
[![JADX](https://img.shields.io/badge/JADX-%E2%89%A51.5-green.svg)](https://github.com/skylot/jadx)

---

## Demo Web

<img width="1376" height="631" alt="image" src="https://github.com/user-attachments/assets/1854fb70-fb74-45ab-aab4-678f9f2136fb" />

See demo @ [watch](https://free.smmall.cloud/MTc4NjMzMDU0MDg1Mw)

---

## Table of contents

- [Why Malimite?](#why-malimite)
- [Malimite vs Malimite-Core](#malimite-vs-malimite-core)
- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Download pre-built CLI](#download-pre-built-cli)
- [Quick start](#quick-start)
- [Web UI & REST API](#web-ui--rest-api)
- [Slack bot](#slack-bot)
- [CI/CD integration](#cicd-integration)
- [Detection engines](#detection-engines)
- [Triage workflow](#triage-workflow)
- [Configuration](#configuration)
- [Project structure](#project-structure)
- [Testing](#testing)
- [Roadmap](#roadmap)
- [Credits & license](#credits--license)

---

## Why Malimite?

[Malimite](https://github.com/LaurieWired/Malimite) is built for researchers who want a rich desktop experience: drag an IPA, browse decompiled Swift/Objective-C, and translate methods with built-in LLM support. That workflow is ideal for interactive reverse engineering.

**Malimite-Core** targets a different problem (and adds Android APK analysis via JADX alongside the iOS Ghidra path):

- Run scans in **CI/CD** on every release build
- Let security teams **triage findings** (false positive, accepted risk, severity override)
- Push **SARIF** into GitHub Code Scanning / GitLab / DefectDojo
- Operate as a **service** (web UI, REST API, Slack bot) without a desktop session
- **Learn rules** from LLM findings so future scans catch the same patterns without API cost

Same Ghidra decompilation DNA. Different deployment model.

---

## Malimite vs Malimite-Core

| | [Malimite](https://github.com/LaurieWired/Malimite) | Malimite-Core |
|---|---|---|
| **Interface** | Desktop GUI (Swing) | Headless CLI + Web SPA + Slack |
| **Primary use** | Interactive RE | Automation & AppSec pipelines |
| **Output** | In-app browsing | SQLite, HTML report, SARIF 2.1 |
| **Security rules** | Manual review | Built-in iOS MASTG/MSTG + Android MASTG catalogs + LLM + learned rules |
| **Triage** | — | Status, severity/CVSS override, reviewer notes |
| **CI/CD** | Manual | GitHub Actions, GitLab CI, Bitbucket Pipelines |
| **LLM providers** | OpenAI (upstream) | OpenAI, Claude, **DeepSeek**, Ollama |
| **License** | Apache 2.0 | Apache 2.0 |

Malimite-Core ports core analysis concepts from Malimite (`GhidraRunner`, `SyntaxParser`, `DemangleSwift`, `DumpClassData.java`, SQLite schema, LLM enrichment patterns) into a modular Maven monorepo with no Swing/AWT dependencies.

---

## Features

| Capability | Description |
|---|---|
| **Ghidra decompilation** | Headless `analyzeHeadless` → C-like pseudocode (iOS Mach-O; Android `lib/arm64-v8a/*.so`) |
| **JADX decompilation** | Android DEX → Java sources via `jadx` CLI, ingested into SQLite |
| **MASTG / MSTG rule engines** | Platform catalogs: iOS (`VulnerabilityCatalog`) + Android (`AndroidVulnerabilityCatalog`) — STORAGE, CRYPTO, NETWORK, PLATFORM, AUTH, CODE, RESILIENCE |
| **LLM enrichment** | Per-function analysis via OpenAI, Claude, DeepSeek, or Ollama (platform-aware prompts) |
| **Security Assessment** | Controls inventory (obfuscation, SSL pinning, root/Frida detection, FLAG_SECURE, …) — separate from vulnerability findings |
| **Self-learning rules** | LLM `detection_regex` validated and persisted per platform (`learned_rules.json` / `learned_rules_android.json`) |
| **Triage workflow** | Mark false positive / accepted risk / fixed; override severity & CVSS |
| **HTML reports** | Vulnerability-centric layout with evidence, PoC, remediation, MASTG/MSTG references; unique issues grouped by `rule_id` |
| **SARIF 2.1** | Native integration with GitHub Code Scanning and other SARIF consumers |
| **Multiple ingress paths** | Web UI, REST API, Slack bot, CLI, watch-folder daemon, CI templates |

---

## Architecture

```
                    ┌──────────────────────────────────────────────┐
                    │              User-facing layer               │
                    │   Web UI · Slack bot · CI/CD · CLI · watcher │
                    └─────────────────────┬────────────────────────┘
                                          │
                                          ▼
              ┌───────────────────────────────────────────────────────┐
              │              malimite-cli.jar  (fat JAR)              │
              │  MalimiteAnalyzer: validate → extract → decompile     │
              │       → vuln scan + optional Assessment + LLM         │
              └─────────────────────┬─────────────────────────────────┘
                     │              │              │              │
                     ▼              ▼              ▼              ▼
              iOS: Ghidra     Android: JADX   SQLite store    LLM providers
              Mach-O +        DEX/Java +      + MASTG/MSTG    OpenAI / Claude /
              DumpClassData   optional Ghidra  + Assessment   DeepSeek / Ollama
                              on arm64 .so     + learned rules
                                          │
                                          ▼
                              Per-scan output directory
                              · *.sqlite   · scan.json
                              · report.html · findings.sarif
                              · analysis.log
```

---

## Prerequisites

| Requirement | Version / notes |
|---|---|
| **Java JDK** | 17+ |
| **Maven** | 3.8+ |
| **Ghidra** | ≥ 11.1 — must contain `support/analyzeHeadless` (required for `.ipa`) |
| **JADX** | ≥ 1.5 — CLI `bin/jadx` (required for `.apk` DEX; set `JADX_HOME`) |
| **Ghidra (Android native)** | Same install as iOS — used for APK `lib/arm64-v8a/*.so` when `GHIDRA_HOME` is set |
| **Python** | 3.10+ (web service & Slack bot only) |
| **LLM API key** | Optional — only when `--llm` is enabled |

Install Ghidra on Debian/Kali:

```bash
sudo apt install ghidra   # or set GHIDRA_HOME to your install path
```

Install JADX (Android APK decompilation):

```bash
# Download a release from https://github.com/skylot/jadx/releases
export JADX_HOME=/opt/jadx   # directory containing bin/jadx
```

---

## Download pre-built CLI

Pre-built fat JARs are published on the
[GitHub Releases page](https://github.com/insomn14/Malimite-Core/releases).
Only Java 17 or newer is required to launch the CLI; Ghidra and/or JADX are
still required for the package types described in [Prerequisites](#prerequisites).

```bash
VERSION=0.1.0
curl -fLO "https://github.com/insomn14/Malimite-Core/releases/download/v${VERSION}/malimite-cli-${VERSION}.jar"
curl -fLO "https://github.com/insomn14/Malimite-Core/releases/download/v${VERSION}/malimite-cli-${VERSION}.jar.sha256"
sha256sum --check "malimite-cli-${VERSION}.jar.sha256"
java -jar "malimite-cli-${VERSION}.jar" --version
```

Each pushed semantic-version tag such as `v0.1.0` is built and tested by
GitHub Actions before the JAR and its SHA-256 checksum are attached to the
release.

---

## Quick start

### 1. Build from source (alternative)

```bash
git clone https://github.com/insomn14/Malimite-Core.git
cd Malimite-Core
mvn -DskipTests package -pl core,cli
# → cli/target/malimite-cli.jar
```

### 2. Scan an IPA or APK (CLI)

```bash
export GHIDRA_HOME=/usr/share/ghidra
export JADX_HOME=/opt/jadx

java -jar cli/target/malimite-cli.jar path/to/MyApp.ipa \
     --ghidra "$GHIDRA_HOME" \
     --out /tmp/malimite-scan \
     --sarif --html

java -jar cli/target/malimite-cli.jar path/to/MyApp.apk \
     --jadx "$JADX_HOME" \
     --ghidra "$GHIDRA_HOME" \
     --out /tmp/malimite-apk-scan \
     --sarif --html
# JADX decompiles DEX; Ghidra decompiles lib/arm64-v8a/*.so when present

# Fast Scan (default): first-party packages/native only. Works without --llm.
java -jar cli/target/malimite-cli.jar path/to/MyApp.apk \
     --jadx "$JADX_HOME" --out /tmp/fast --llm-mode fast

# Full Scan: include third-party Java/native. --llm-mode selects scope even without --llm.
java -jar cli/target/malimite-cli.jar path/to/MyApp.apk \
     --jadx "$JADX_HOME" --out /tmp/full --llm-mode full
```

**Outputs:**

| File | Purpose |
|---|---|
| `report.html` | Human-readable security report |
| `findings.sarif` | Machine-readable for Code Scanning / DefectDojo |
| `*.sqlite` | Full decompilation + findings database |
| `scan.json` | Bundle metadata summary |

### 3. Scan with LLM enrichment

```bash
# DeepSeek
DEEPSEEK_API_KEY=sk-... \
  java -jar cli/target/malimite-cli.jar MyApp.ipa \
       --ghidra "$GHIDRA_HOME" --out /tmp/scan --sarif --html \
       --llm --llm-provider deepseek --llm-model deepseek-v4-flash \
       --llm-mode find_vulns --fail-on HIGH

# Claude
ANTHROPIC_API_KEY=sk-ant-... \
  java -jar cli/target/malimite-cli.jar MyApp.ipa \
       --ghidra "$GHIDRA_HOME" --out /tmp/scan --sarif --html \
       --llm --llm-provider claude --llm-mode find_vulns
```

---

## Web UI & REST API

```bash
cd web
cp .env.example .env    # optional: GHIDRA_HOME, API_KEY, LLM defaults
./run.sh
# → http://localhost:7070
```

Drop an `.ipa` or `.apk` on the upload page (enable **Security Assessment** via the checkbox — on by default). The FastAPI service runs the CLI in the background and exposes everything under `/api/v1/*`. OpenAPI docs: `http://localhost:7070/docs`. The UI groups findings by `rule_id` (unique issues) and has a dedicated **Assessment** tab for controls inventory.

**Key endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/scans` | Upload IPA or APK (multipart form; `assessment_enabled`) |
| `GET` | `/api/v1/scans/{id}/vulnerabilities` | List findings |
| `GET` | `/api/v1/scans/{id}/assessments` | Security Assessment controls inventory |
| `PATCH` | `/api/v1/scans/{id}/vulnerabilities/{vuln_id}` | Triage (status, severity override) |
| `GET` | `/api/v1/scans/{id}/report` | HTML report |
| `GET` | `/api/v1/scans/{id}/sarif` | SARIF download |
| `GET` | `/api/v1/scans/{id}/functions` | Browse decompiled functions |

---

## Slack bot

Standalone bot using Slack Socket Mode — **no public URL or ngrok required**.

```bash
cd bot/python
cp .env.example .env
# Set SLACK_APP_TOKEN (xapp-...) and SLACK_BOT_TOKEN (xoxb-...)
./run.sh
```

DM the bot an `.ipa` or `.apk` file → it replies with a severity-sorted summary, HTML report, and SARIF attachment. See [`bot/python/README.md`](bot/python/README.md) for Slack App setup.

---

## CI/CD integration

Ready-to-use templates:

| Platform | File |
|----------|------|
| GitHub Actions | [`.github/workflows/ipa-scan.yml`](.github/workflows/ipa-scan.yml) |
| GitLab CI | [`.gitlab/malimite.yml`](.gitlab/malimite.yml) |
| Bitbucket Pipelines | [`bitbucket-pipelines.yml`](bitbucket-pipelines.yml) |

GitHub Actions uploads SARIF to the **Security → Code scanning** tab automatically. Stock templates target `.ipa` + Ghidra; for APK scans set `JADX_HOME` (Docker image includes JADX at `/opt/jadx`) alongside `GHIDRA_HOME`. Optional secrets: `LLM_PROVIDER`, `DEEPSEEK_API_KEY` / `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`.

---

## Detection engines

### Built-in MASTG / MSTG rules

Platform-specific catalogs derived from [OWASP MASTG](https://mas.owasp.org/MASTG/) (legacy iOS IDs keep `MSTG-*`):

| Platform | Catalog | Coverage |
|----------|---------|----------|
| **iOS** | `VulnerabilityCatalog` | Mach-O / plist / Info.plist patterns — STORAGE, CRYPTO, NETWORK, PLATFORM, AUTH, CODE, RESILIENCE |
| **Android** | `AndroidVulnerabilityCatalog` | JADX Java, manifest/NSC, and optional Ghidra arm64 `.so` rules |

| Category | Examples (iOS / Android) |
|----------|--------------------------|
| **STORAGE** | NSUserDefaults / SharedPreferences misuse, keychain & credential leaks |
| **CRYPTO** | MD5, SHA-1, DES/RC4, ECB mode, weak RNG |
| **NETWORK** | Cleartext HTTP, ATS / NSC misconfig, missing cert pinning |
| **PLATFORM** | UIWebView, exported components, unvalidated URL schemes |
| **AUTH** | Biometrics without Keychain/Keystore binding |
| **CODE** | Unsafe C functions, missing stack canaries / ELF hardening |
| **RESILIENCE** | Jailbreak / root / anti-debug / Frida detection gaps |

Each finding includes rule ID, severity, CVSS, CWE, evidence, PoC steps, remediation, and MASTG/MSTG reference URL. Web UI and HTML reports count **unique issues by `rule_id`** (same issue across many assets = one open issue).

### Security Assessment

Enable (default) with `--assessment` or the web **Security Assessment** checkbox. Malimite inventories implemented protections — obfuscation (R8 vs commercial vendors), root/jailbreak & Frida detection, SSL pinning style, FLAG_SECURE, native ELF hardening, and more — as `PRESENT` / `PARTIAL` / `ABSENT` / `UNKNOWN`. Results appear in the **Assessment** tab and the HTML report section *Security Controls Assessment*, and are **not** mixed into vulnerability severity counts.

### LLM enrichment

Supported providers: **OpenAI**, **Anthropic Claude**, **DeepSeek**, **Ollama**.

Modes: `summarize` (Fast Scan) · `find_vulns` (Full Scan) · `auto_fix` · `offensive`

| Mode | Aliases | Scope | Purpose |
|------|---------|-------|---------|
| **Fast Scan** | `summarize`, `fast`, `fast_scan` | First-party app packages + first-party native libs | Cheap MSTG + optional summarize-style LLM on in-scope code only |
| **Full Scan** | `find_vulns`, `vulns`, `full`, `full_scan` | All ingested targets including 3rd-party Java/native | Structured vulnerabilities (+ learned rules when regex self-validates) |
| **Auto Fix** | `auto_fix`, `autofix`, `fix` | First-party (same as Fast Scan) | Idiomatic reconstruct of decompiled code |
| **Offensive** | `offensive`, `frida`, `bypass` | First-party **union** a narrow security-SDK allowlist (root/JB/Frida/RASP/pinning) | Frida bypass/intercept playbooks (requires `--llm`) |

**Scope notes**

- First-party Java/Kotlin prefixes are derived from **each scan's** `applicationId` / bundle id (not a hardcoded app list). Example: `com.example.foo.staging` → exact id plus parent `com.example.foo.` (siblings such as `com.example.foo.sdk` are included). Matching is `equals` or `startsWith(prefix + ".")`, so `com.example.foox` is not in-scope. Extra prefixes: `--include-package`.
- First-party native: `.so` names that contain the last meaningful id segments (length ≥ 4, skipping `com`/`android`/`staging`/…) or generic app JNI (`libnative-lib.so`, weak heuristic). Vendor libs (ObjectBox, Bugsnag, Avif, Conscrypt, …) are skipped in Fast/Auto Fix. Offensive re-includes a small security-lib name list (`toolChecker`, Talsec, AppGuard, Promon, Conscrypt, …) but still skips generic third-party.
- Manifest / NSC / Info.plist / exported components stay in-scope for every mode. Assessment still sees 3rd-party SDK markers (RootBeer, pinning, RASP) even when Fast Scan skips those packages for MSTG/LLM/Ghidra.
- Out-of-scope `.so` files are skipped **before** Ghidra. LLM enrichment and function-level MSTG hits honor the same scope.

**Offensive** mode is for authorized mobile penetration testing only. It stores structured `offensive_targets` JSON in `LlmFindings` (not promoted into Vulnerabilities or learned rules). The web UI shows a dedicated **Offensive** campaign tab (kill-chain phases + Frida kit export).

When LLM finds a vulnerability (`find_vulns` / Full Scan), it returns a `detection_regex`. Regexes that self-validate against the source function are saved per platform — `~/.malimite/learned_rules.json` (iOS) or `learned_rules_android.json` (Android) — and reused on future scans **without further LLM calls**. Hollow placeholders such as `...` are rejected.

### DeepSeek models

| Model | Use case |
|-------|----------|
| `deepseek-v4-flash` | Default — fast, 1M context |
| `deepseek-v4-pro` | Higher quality analysis |
| `deepseek-chat` | Legacy alias (deprecated 2026-07) |
| `deepseek-reasoner` | Chain-of-thought reasoning |

---

## Triage workflow

Security reviewers can adjust findings without re-scanning:

| Field | Values | Effect |
|-------|--------|--------|
| `status` | `open`, `false_positive`, `accepted_risk`, `fixed` | Suppressed statuses excluded from Risk Posture & SARIF |
| `override_severity` | `CRITICAL` … `INFO` | Replaces original in counts, sorting, and report |
| `override_cvss_score` | `0.0`–`10.0` | Replaces original CVSS |
| `override_note` | free text | Shown in audit trail |

Reports (`report.html`, `findings.sarif`) regenerate automatically after each triage update.

---

## Configuration

### CLI flags

```
malimite [OPTIONS] <ipa|apk>
  -o, --out=<dir>          Output directory
  -g, --ghidra=<dir>       Ghidra install (or env GHIDRA_HOME) — iOS Mach-O + Android arm64 .so
  -j, --jadx=<dir>         JADX install (or env JADX_HOME) — Android DEX/Java
      --sarif              Write findings.sarif
      --html               Write report.html
      --llm                Enable LLM enrichment
      --llm-provider=<x>   openai | claude | deepseek | ollama
      --llm-mode=<x>       fast | summarize | fast_scan   (Fast Scan, first-party)
                           full | find_vulns | full_scan  (Full Scan, includes 3rd-party)
                           auto_fix                       (first-party reconstruct)
                           offensive                      (first-party + security SDKs; requires --llm)
      --include-package=<p> Extra first-party Java package prefix (repeatable)
      --llm-model=<x>      Override default model per provider
      --assessment / --no-assessment
                           Security-controls Assessment (default: on)
      --fail-on=<severity> Exit 1 if findings ≥ HIGH|MEDIUM|LOW
```

### Environment variables

| Variable | Purpose |
|----------|---------|
| `GHIDRA_HOME` | Ghidra install (iOS Mach-O; Android `lib/arm64-v8a/*.so`) |
| `JADX_HOME` / `JADX_PATH` | JADX install root or binary path (Android DEX) |
| `MALIMITE_LEARNED_RULES` / `MALIMITE_LEARNED_RULES_IOS` | iOS learned-rules JSON (default `~/.malimite/learned_rules.json`) |
| `MALIMITE_LEARNED_RULES_ANDROID` | Android learned-rules JSON (default `~/.malimite/learned_rules_android.json`) |
| `LLM_PROVIDER` | `openai` · `claude` · `deepseek` · `ollama` · `none` |
| `OPENAI_API_KEY` | OpenAI API key |
| `ANTHROPIC_API_KEY` | Anthropic API key |
| `DEEPSEEK_API_KEY` | DeepSeek API key |
| `DEEPSEEK_BASE_URL` | Default `https://api.deepseek.com` |
| `OLLAMA_BASE_URL` | Default `http://localhost:11434` |
| `LLM_MODEL` / `LLM_MAX_TOKENS` | Override provider defaults |
| `SCAN_DIR` | Web service scan output directory |
| `API_KEY` | Optional `X-Api-Key` for web API |

---

## Project structure

```
Malimite-Core/
├── core/           # Analysis engine (Ghidra, JADX, MASTG scanners, Assessment, LLM, SARIF, HTML)
├── cli/            # malimite-cli.jar entry point
├── web/            # FastAPI + SPA (recommended deployment)
├── bot/python/     # Slack bot (Socket Mode)
├── deploy/         # Dockerfile + docker-compose
├── watcher/        # inotify drop-folder daemon
├── api/            # Legacy Javalin REST (Docker stack compat)
├── worker/         # Legacy Redis queue consumer
├── .github/        # GitHub Actions + SARIF upload
└── PHASES.md       # Development roadmap
```

---

## Testing

```bash
mvn test -pl core
```

Unit tests in `core/` cover IPA/APK validation & extraction, Android manifest/NSC ingest, Assessment scanner, MASTG catalogs, LLM providers, SARIF schema, HTML reporter (including triage severity overrides and unique `rule_id` grouping), and platform-scoped learned-rules persistence.

---

## Roadmap

See [`PHASES.md`](PHASES.md) for the full development plan. Highlights:

- ✅ Core Ghidra pipeline, MSTG/MASTG scanner, LLM, SARIF/HTML, CI templates
- ✅ Android APK analysis (JADX DEX + optional Ghidra arm64 `.so`)
- ✅ Security Assessment mode (PRESENT / PARTIAL / ABSENT / UNKNOWN)
- 🔄 Closure items: real-IPA/APK integration test, cross-reference REST API
- 📋 Next major phase: **Observability** (Prometheus metrics, enriched health checks)
- 📋 Future: security hardening, Helm/Kubernetes, enterprise SSO

---

## Credits & license

**Malimite-Core** is a headless reimplementation inspired by [**Malimite**](https://github.com/LaurieWired/Malimite) by [LaurieWired](https://github.com/LaurieWired). Malimite is an iOS and macOS decompiler built on Ghidra with direct Swift/Objective-C support and built-in LLM method translation — if you need an interactive desktop tool, start there.

Key upstream concepts ported (with Swing removed):

- `GhidraProject` → `GhidraRunner`
- `DynamicDecompile` / `FileProcessing` → `MalimiteAnalyzer` / `IpaExtractor`
- `AIBackend` → `LlmEnricher` (+ Claude, DeepSeek, Ollama providers)
- `DecompilerBridge/ghidra/DumpClassData.java` → bundled Ghidra post-script
- `SQLiteDBHandler` → `SqliteStore`

Licensed under the **Apache License 2.0**, consistent with upstream Malimite. See [Malimite LICENSE](https://github.com/LaurieWired/Malimite/blob/main/LICENSE).

---

## Contributing

Issues and pull requests are welcome. Before opening a PR:

1. Run `mvn test -pl core`
2. Keep changes focused — Malimite-Core favors minimal, headless diffs
3. Credit Malimite when porting additional upstream functionality

**Star [Malimite](https://github.com/LaurieWired/Malimite)** if you find this project useful — and consider starring Malimite-Core too once it's on GitHub.
