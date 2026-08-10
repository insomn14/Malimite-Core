# Mailmite-Core

**Headless iOS static analysis platform** — decompile `.ipa` files with Ghidra, scan against OWASP MSTG rules, optionally enrich with LLM, and deliver findings through a web UI, REST API, Slack bot, or CI/CD pipeline.

> Inspired by and ported from [**Malimite**](https://github.com/LaurieWired/Malimite) by [@LaurieWired](https://github.com/LaurieWired) — the excellent interactive iOS/macOS decompiler. Mailmite-Core takes the same Ghidra-backed analysis pipeline and refactors it for **automation, team workflows, and continuous security scanning** instead of desktop GUI use.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-17+-orange.svg)](https://openjdk.org/)
[![Ghidra](https://img.shields.io/badge/Ghidra-%E2%89%A511.1-purple.svg)](https://ghidra-sre.org/)

---

## Table of contents

- [Why Mailmite?](#why-mailmite)
- [Malimite vs Mailmite-Core](#malimite-vs-mailmite-core)
- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
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

## Why Mailmite?

[Malimite](https://github.com/LaurieWired/Malimite) is built for researchers who want a rich desktop experience: drag an IPA, browse decompiled Swift/Objective-C, and translate methods with built-in LLM support. That workflow is ideal for interactive reverse engineering.

**Mailmite-Core** targets a different problem:

- Run scans in **CI/CD** on every release build
- Let security teams **triage findings** (false positive, accepted risk, severity override)
- Push **SARIF** into GitHub Code Scanning / GitLab / DefectDojo
- Operate as a **service** (web UI, REST API, Slack bot) without a desktop session
- **Learn rules** from LLM findings so future scans catch the same patterns without API cost

Same Ghidra decompilation DNA. Different deployment model.

---

## Malimite vs Mailmite-Core

| | [Malimite](https://github.com/LaurieWired/Malimite) | Mailmite-Core |
|---|---|---|
| **Interface** | Desktop GUI (Swing) | Headless CLI + Web SPA + Slack |
| **Primary use** | Interactive RE | Automation & AppSec pipelines |
| **Output** | In-app browsing | SQLite, HTML report, SARIF 2.1 |
| **Security rules** | Manual review | 26 built-in MSTG rules + LLM + learned rules |
| **Triage** | — | Status, severity/CVSS override, reviewer notes |
| **CI/CD** | Manual | GitHub Actions, GitLab CI, Bitbucket Pipelines |
| **LLM providers** | OpenAI (upstream) | OpenAI, Claude, **DeepSeek**, Ollama |
| **License** | Apache 2.0 | Apache 2.0 |

Mailmite-Core ports core analysis concepts from Malimite (`GhidraRunner`, `SyntaxParser`, `DemangleSwift`, `DumpClassData.java`, SQLite schema, LLM enrichment patterns) into a modular Maven monorepo with no Swing/AWT dependencies.

---

## Features

| Capability | Description |
|---|---|
| **Ghidra decompilation** | Headless `analyzeHeadless` → C-like pseudocode per function, stored in SQLite |
| **MSTG rule engine** | 26 static rules across STORAGE, CRYPTO, NETWORK, PLATFORM, AUTH, CODE, RESILIENCE |
| **LLM enrichment** | Per-function analysis via OpenAI, Claude, DeepSeek, or Ollama |
| **Security Assessment** | Controls inventory (obfuscation, SSL pinning, root/Frida detection, FLAG_SECURE, …) — separate from vulnerability findings |
| **Self-learning rules** | LLM `detection_regex` validated and persisted to `~/.mailmite/learned_rules.json` |
| **Triage workflow** | Mark false positive / accepted risk / fixed; override severity & CVSS |
| **HTML reports** | Vulnerability-centric layout with evidence, PoC, remediation, MSTG references |
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
              │              mailmite-cli.jar  (fat JAR)              │
              │  MailmiteAnalyzer: validate → extract → Ghidra → scan │
              └───────────────────────────────────────────────────────┘
                     │                    │                    │
                     ▼                    ▼                    ▼
              Ghidra headless      SQLite store         LLM providers
              + DumpClassData      + MSTG rules         OpenAI / Claude /
              decompiler           + learned rules      DeepSeek / Ollama
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

## Quick start

### 1. Build

```bash
git clone https://github.com/insomn14/Mailmite-Core.git
cd Mailmite-Core
mvn -DskipTests package -pl core,cli
# → cli/target/mailmite-cli.jar
```

### 2. Scan an IPA or APK (CLI)

```bash
export GHIDRA_HOME=/usr/share/ghidra
export JADX_HOME=/opt/jadx

java -jar cli/target/mailmite-cli.jar path/to/MyApp.ipa \
     --ghidra "$GHIDRA_HOME" \
     --out /tmp/mailmite-scan \
     --sarif --html

java -jar cli/target/mailmite-cli.jar path/to/MyApp.apk \
     --jadx "$JADX_HOME" \
     --ghidra "$GHIDRA_HOME" \
     --out /tmp/mailmite-apk-scan \
     --sarif --html
# JADX decompiles DEX; Ghidra decompiles lib/arm64-v8a/*.so when present
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
  java -jar cli/target/mailmite-cli.jar MyApp.ipa \
       --ghidra "$GHIDRA_HOME" --out /tmp/scan --sarif --html \
       --llm --llm-provider deepseek --llm-model deepseek-v4-flash \
       --llm-mode find_vulns --fail-on HIGH

# Claude
ANTHROPIC_API_KEY=sk-ant-... \
  java -jar cli/target/mailmite-cli.jar MyApp.ipa \
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

Drop an `.ipa` on the upload page. The FastAPI service runs the CLI in the background and exposes everything under `/api/v1/*`. OpenAPI docs: `http://localhost:7070/docs`.

**Key endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/scans` | Upload IPA (multipart form) |
| `GET` | `/api/v1/scans/{id}/vulnerabilities` | List findings |
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

DM the bot an `.ipa` file → it replies with a severity-sorted summary, HTML report, and SARIF attachment. See [`bot/python/README.md`](bot/python/README.md) for Slack App setup.

---

## CI/CD integration

Ready-to-use templates:

| Platform | File |
|----------|------|
| GitHub Actions | [`.github/workflows/ipa-scan.yml`](.github/workflows/ipa-scan.yml) |
| GitLab CI | [`.gitlab/mailmite.yml`](.gitlab/mailmite.yml) |
| Bitbucket Pipelines | [`bitbucket-pipelines.yml`](bitbucket-pipelines.yml) |

GitHub Actions uploads SARIF to the **Security → Code scanning** tab automatically. Set repository secrets: `GHIDRA_HOME`, optional `LLM_PROVIDER`, `DEEPSEEK_API_KEY` / `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`.

---

## Detection engines

### Built-in MSTG rules

26 rules derived from the [OWASP MSTG](https://github.com/OWASP/owasp-mstg) iOS checklist:

| Category | Examples |
|----------|----------|
| **STORAGE** | Hardcoded API keys, NSUserDefaults misuse, keychain accessibility |
| **CRYPTO** | MD5, SHA-1, DES/RC4, ECB mode, weak RNG |
| **NETWORK** | Cleartext HTTP, `NSAllowsArbitraryLoads`, missing cert pinning |
| **PLATFORM** | UIWebView, unvalidated URL schemes |
| **AUTH** | Biometrics without Keychain binding |
| **CODE** | Unsafe C functions, missing stack canaries |
| **RESILIENCE** | No jailbreak / anti-debug / Frida detection |

Each finding includes rule ID, severity, CVSS, CWE, evidence, PoC steps, remediation, and MSTG reference URL.

### Security Assessment

Enable (default) with `--assessment` or the web **Security Assessment** checkbox. Mailmite inventories implemented protections — obfuscation (R8 vs commercial vendors), root/jailbreak & Frida detection, SSL pinning style, FLAG_SECURE, native ELF hardening, and more — as `PRESENT` / `PARTIAL` / `ABSENT` / `UNKNOWN`. Results appear in the **Assessment** tab and the HTML report section *Security Controls Assessment*, and are **not** mixed into vulnerability severity counts.

### LLM enrichment

Supported providers: **OpenAI**, **Anthropic Claude**, **DeepSeek**, **Ollama**.

Modes: `summarize` · `find_vulns` · `auto_fix`

When LLM finds a vulnerability, it returns a `detection_regex`. Regexes that self-validate against the source function are saved to `~/.mailmite/learned_rules.json` and reused on future scans **without further LLM calls**.

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
mailmite [OPTIONS] <ipa|apk>
  -o, --out=<dir>          Output directory
  -g, --ghidra=<dir>       Ghidra install (or env GHIDRA_HOME) — iOS Mach-O + Android arm64 .so
  -j, --jadx=<dir>         JADX install (or env JADX_HOME) — Android DEX/Java
      --sarif              Write findings.sarif
      --html               Write report.html
      --llm                Enable LLM enrichment
      --llm-provider=<x>   openai | claude | deepseek | ollama
      --llm-mode=<x>       summarize | find_vulns | auto_fix
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
| `MAILMITE_LEARNED_RULES` / `MAILMITE_LEARNED_RULES_IOS` | iOS learned-rules JSON (default `~/.mailmite/learned_rules.json`) |
| `MAILMITE_LEARNED_RULES_ANDROID` | Android learned-rules JSON (default `~/.mailmite/learned_rules_android.json`) |
| `LLM_PROVIDER` | `openai` · `claude` · `deepseek` · `ollama` · `none` |
| `OPENAI_API_KEY` | OpenAI API key |
| `ANTHROPIC_API_KEY` | Anthropic API key |
| `DEEPSEEK_API_KEY` | DeepSeek API key |
| `DEEPSEEK_BASE_URL` | Default `https://api.deepseek.com` |
| `OLLAMA_BASE_URL` | Default `http://localhost:11434` |
| `LLM_MODEL` / `LLM_MAX_TOKENS` | Override provider defaults |
| `MAILMITE_LEARNED_RULES` | Path to learned-rules JSON |
| `SCAN_DIR` | Web service scan output directory |
| `API_KEY` | Optional `X-Api-Key` for web API |

---

## Project structure

```
Mailmite-Core/
├── core/           # Analysis engine (Ghidra, MSTG scanner, LLM, SARIF, HTML)
├── cli/            # mailmite-cli.jar entry point
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

47 unit tests cover IPA validation, plist/Mach-O parsing, LLM providers, SARIF schema, HTML reporter (including triage severity overrides), and learned-rules persistence.

---

## Roadmap

See [`PHASES.md`](PHASES.md) for the full development plan. Highlights:

- ✅ Core Ghidra pipeline, MSTG scanner, LLM, SARIF/HTML, CI templates
- 🔄 Closure items: real-IPA integration test, cross-reference REST API
- 📋 Next major phase: **Observability** (Prometheus metrics, enriched health checks)
- 📋 Future: security hardening, Helm/Kubernetes, enterprise SSO

---

## Credits & license

**Mailmite-Core** is a headless reimplementation inspired by [**Malimite**](https://github.com/LaurieWired/Malimite) by [LaurieWired](https://github.com/LaurieWired). Malimite is an iOS and macOS decompiler built on Ghidra with direct Swift/Objective-C support and built-in LLM method translation — if you need an interactive desktop tool, start there.

Key upstream concepts ported (with Swing removed):

- `GhidraProject` → `GhidraRunner`
- `DynamicDecompile` / `FileProcessing` → `MailmiteAnalyzer` / `IpaExtractor`
- `AIBackend` → `LlmEnricher` (+ Claude, DeepSeek, Ollama providers)
- `DecompilerBridge/ghidra/DumpClassData.java` → bundled Ghidra post-script
- `SQLiteDBHandler` → `SqliteStore`

Licensed under the **Apache License 2.0**, consistent with upstream Malimite. See [Malimite LICENSE](https://github.com/LaurieWired/Malimite/blob/main/LICENSE).

---

## Contributing

Issues and pull requests are welcome. Before opening a PR:

1. Run `mvn test -pl core`
2. Keep changes focused — Mailmite-Core favors minimal, headless diffs
3. Credit Malimite when porting additional upstream functionality

**Star [Malimite](https://github.com/LaurieWired/Malimite)** if you find this project useful — and consider starring Mailmite-Core too once it's on GitHub.
