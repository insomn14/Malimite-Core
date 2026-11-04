# Malimite-Core

**Headless iOS & Android static analysis platform** — decompile `.ipa` (Ghidra) and `.apk` (JADX for DEX, optional Ghidra for arm64 `.so`), scan against OWASP MASTG/MSTG rules, optionally enrich with LLM, and deliver findings through a web UI, REST API, Slack bot, or CI/CD pipeline.

> Inspired by and ported from [**Malimite**](https://github.com/LaurieWired/Malimite) by [@LaurieWired](https://github.com/LaurieWired) — the excellent interactive iOS/macOS decompiler. Malimite-Core takes the same Ghidra-backed analysis pipeline and refactors it for **automation, team workflows, and continuous security scanning** instead of desktop GUI use.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-17+-orange.svg)](https://openjdk.org/)
[![Ghidra](https://img.shields.io/badge/Ghidra-12.0.x-purple.svg)](https://ghidra-sre.org/)
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
- [AI Assistant](#ai-assistant)
  - [Functions tab (Functions Explorer)](#functions-tab-functions-explorer)
  - [Claude Pro/Max OAuth](#claude-promax-oauth-no-separately-billed-api-key)
- [Slack bot](#slack-bot)
- [CI/CD integration](#cicd-integration)
- [Detection engines](#detection-engines)
- [Triage workflow](#triage-workflow)
- [AI Fix](#ai-fix)
- [Auto Enhance](#auto-enhance)
- [HTML Report](#html-report)
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
| **AI Fix** | Per-finding LLM rewrite of Description/Evidence/Risk/PoC/Remediation, stored as reversible overrides |
| **Auto Enhance** | Bulk AI Fix: runs across many selected findings as a server-side background job, with live progress, Cancel Batch, and per-finding Retry |
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
| **Ghidra** | 12.0.x (the web Docker image ships 12.0.4) — must contain `support/analyzeHeadless` (required for `.ipa`). 11.1.2 rejects the headless arguments the scan passes (`Bad argument: -enableAnalyzer`); 12.1+ is untested (see `web/app/config.py`). Headless also needs the JDK font libraries (`libharfbuzz0b`, `libfontconfig1`, `libfreetype6` on Debian) |
| **JADX** | ≥ 1.5 — CLI `bin/jadx` (required for `.apk` DEX; set `JADX_HOME`) |
| **Droid ASC** (optional) | `droidasc` on `PATH` (or `ASC_HOME`/`python -m droidasc`) — alternate Android decompiler, `--decompiler asc`. Falls back to JADX automatically when unavailable (see below) |
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

Install Droid ASC (optional — faster on-demand Android decompiler, `--decompiler asc`):

```bash
pip install droidasc   # or: pipx install droidasc (keeps it out of the system Python env)
# the `droidasc` console script now needs to be on PATH wherever the CLI process actually runs
```

`AscRunner` resolves the binary as `--asc-home <dir>`/`ASC_HOME` (a source
checkout, run via `python -m droidasc`) → a `droidasc` script on `PATH`, and
verifies it can actually launch (not just that the install step succeeded)
before ever trying to use it — if that check fails, the scan transparently
falls back to JADX instead of erroring out. **systemd units do not inherit
the login shell's `PATH`** (user services default to `PATH=/usr/local/bin:/usr/bin`),
so a `pip install --user`/`pipx install` of `droidasc` under `~/.local/bin` is
invisible to a service unless that directory is added explicitly:

```ini
# ~/.config/systemd/user/malimite-web.service
[Service]
Environment=PATH=/home/%u/.local/bin:/usr/local/bin:/usr/bin
```

Without this, `--decompiler asc` silently (and correctly, per the fallback
above) runs JADX instead — nothing breaks, but ASC never actually gets used.
Confirm which one ran from a scan's own log: `Decompiler backend: asc` vs.
`Decompiler backend: jadx` / `ASC unavailable (...); falling back to JADX`.

---

## Download pre-built CLI

Pre-built fat JARs are published on the
[GitHub Releases page](https://github.com/insomn14/Malimite-Core/releases).
Only Java 17 or newer is required to launch the CLI; Ghidra and/or JADX are
still required for the package types described in [Prerequisites](#prerequisites).

```bash
VERSION=0.3.0   # see https://github.com/insomn14/Malimite-Core/releases for the latest
curl -fLO "https://github.com/insomn14/Malimite-Core/releases/download/v${VERSION}/malimite-cli-${VERSION}.jar"
curl -fLO "https://github.com/insomn14/Malimite-Core/releases/download/v${VERSION}/malimite-cli-${VERSION}.jar.sha256"
sha256sum --check "malimite-cli-${VERSION}.jar.sha256"
java -jar "malimite-cli-${VERSION}.jar" --version
```

Each pushed semantic-version tag such as `v0.3.0` is built and tested by
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

**Split-APK bundles (`.xapk`):** pass the bundle like any other package. Malimite merges the base APK and the
`split_config.*` / feature splits into one analysis APK (`<name>.merged.apk`, written next to the other outputs; not
installable), so DEX, the manifest and the native libraries that live in `split_config.arm64_v8a.apk` are all analysed
together. The base APK is taken from `manifest.json` when the bundle has one, else from `base.apk`, else from the only APK
whose own manifest has no `split` attribute. OBB expansion files are ignored. `scan.json` records `sourcePackage`,
`bundleBaseApk` and `bundleSplits`. The bundle is untrusted input: entry names are validated and the data read is capped
at 2 GiB.

**Outputs:**

| File | Purpose |
|---|---|
| `report.html` | Bilingual VA report — see [HTML Report](#html-report) |
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

Drop an `.ipa`, `.apk` or `.xapk` on the upload page (enable **Security Assessment** via the checkbox — on by default). The FastAPI service runs the CLI in the background and exposes everything under `/api/v1/*`. OpenAPI docs: `http://localhost:7070/docs`. The UI groups findings by `rule_id` (unique issues) and has a dedicated **Assessment** tab for controls inventory.

**Key endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/scans` | Upload IPA or APK (multipart form; `assessment_enabled`) |
| `GET` | `/api/v1/scans/{id}/vulnerabilities` | List findings |
| `GET` | `/api/v1/scans/{id}/assessments` | Security Assessment controls inventory |
| `PATCH` | `/api/v1/scans/{id}/vulnerabilities/{vuln_id}` | Triage (status, severity override) |
| `POST` | `/api/v1/scans/{id}/vulnerabilities/{vuln_id}/ai-fix` | AI Fix — LLM-rewrite Description/Evidence/Risk/PoC/Remediation |
| `POST` | `/api/v1/scans/{id}/vulnerabilities/{vuln_id}/ai-fix/revert` | Revert an applied AI Fix |
| `POST` | `/api/v1/scans/{id}/auto-enhance` | Auto Enhance — start a bulk AI Fix job over many findings |
| `GET` | `/api/v1/scans/{id}/auto-enhance` | Active job (if any) + this scan's Activity Log, newest first |
| `GET` | `/api/v1/scans/{id}/auto-enhance/jobs/{job_id}` | Poll one job's live/persisted progress |
| `POST` | `/api/v1/scans/{id}/auto-enhance/jobs/{job_id}/cancel` | Cancel Batch — skip findings not started yet |
| `POST` | `/api/v1/scans/{id}/auto-enhance/jobs/{job_id}/items/{vuln_id}/retry` | Retry one failed/cancelled finding inside the same run |
| `GET` | `/api/v1/scans/{id}/report` | HTML report |
| `GET` | `/api/v1/scans/{id}/sarif` | SARIF download |
| `GET` | `/api/v1/scans/{id}/functions` | Browse decompiled functions |

---

## AI Assistant

After a scan finishes, the web UI shows an **AI Assistant** tab: a chat with an LLM agent that can use the scan's data as tools and reverse engineer a specific class or function on demand.

| Tool | What it does |
|---|---|
| `scan_overview`, `list_classes`, `search_code`, `get_source`, `search_strings`, `get_vulnerabilities`, `get_references` | Read-only queries over the scan's SQLite (stored decompiled code, strings, findings, call graph when present) |
| `get_assessments` | The Security Assessment inventory (root/jailbreak, Frida, anti-debug, pinning, FLAG_SECURE, obfuscation, ...). Reports `UNKNOWN` as unknown and warns when a bytecode VM may hide checks; says so when a scan has no Assessment |
| `get_manifest` | App configuration: Android package/SDK/debuggable/backup, permissions, components (with `exported`), deep links, native libs; iOS bundle/team/provisioning, Info.plist, entitlements, Mach-O flags. Overview first, then paged sections with a substring filter. Server paths are never exposed |
| `decompile` | Fresh single-class decompile: `asc` (Android, fast), `jadx` (Android), `ghidra` (iOS Mach-O, or Android `.so` via `lib`). Results are cached |
| `recommend_hook_targets` | Recon-only, deterministic (no extra LLM call) ranking of symbols worth a Frida hook for AUTHORIZED pentest work, built from this scan's vulnerabilities and Security Assessment (SSL pinning, root/jailbreak, anti-debug, crypto/keychain). Confidence: HIGH (known symbol + call graph) / MEDIUM (known symbol only) / LOW (assessment text only) |

- **Config:** uses the scan's LLM provider/model by default (overridable per chat). The API key comes from the **server's** `web/.env` (`OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `DEEPSEEK_API_KEY`, or `OLLAMA_BASE_URL`), never from a per-upload key. Optional: `CHAT_MAX_TURNS`, `CHAT_MAX_OUTPUT_TOKENS`, `CHAT_MAX_CONTINUATIONS`, `CHAT_TOOL_CAP`, `HEAVY_CONCURRENCY`, `GHIDRA_ONDEMAND_TIMEOUT`. An answer cut off by the output limit is continued automatically and shown (and saved) as one message (default 5400).
- **Storage:** chat history and the decompile cache live in `<scan-dir>/chat.sqlite`; the scan database is opened read-only.
- **Ghidra on demand:** the scan deletes its Ghidra project, so the first `ghidra` request per binary re-imports and analyzes it into a persistent `<scan-dir>/ghidra-proj/` (minutes: measured 3.6 min for a 50 MB Mach-O, seconds for a small `.so`; disk about 1.2x the binary, 60 MB measured); later requests reopen it (`-process -noanalysis`, about 4 s).
- **API:** `POST /api/v1/scans/{id}/chat` (SSE stream), `GET /api/v1/scans/{id}/chat`, `DELETE /api/v1/scans/{id}/chat/{session_id}`.
- **Safety:** tools cannot run commands, write files or reach the network, and tool output is treated as untrusted data (decompiled code can contain prompt injection). Rebuild the CLI JAR after upgrading: the web service shells out to `io.malimite.core.OnDemandDecompiler` in it. Use only on software you are authorized to analyze.
- **Access control:** the chat spends the server's LLM quota. Set `API_KEY` (UI field "API Key", header `X-Api-Key`; compared in constant time). `deploy/web-compose.yml` publishes the port on `127.0.0.1` only; set `MALIMITE_BIND=0.0.0.0` together with `API_KEY` to expose it. Chat requests are capped globally (`CHAT_RATE_PER_MIN`, default 30). The server logs a warning at startup when `API_KEY` is empty.
- **Container:** the web image runs as an unprivileged user (uid 10001). Its entrypoint chowns an existing root-owned scan volume once, then drops privileges. Decompiler subprocesses get an allowlisted environment (no LLM or API keys).
- **Stored keys:** a per-upload LLM key is only used while the scan runs and is no longer written to `meta.json`; older plaintext keys are removed at startup.

### Functions tab (Functions Explorer)

A JADX-GUI-style browser for everything a scan decompiled: a resizable, searchable file tree on the left (classes grouped by package, methods under each class) and a source viewer on the right with syntax highlighting, an outline dropdown to jump to a method, and cross-tab links (e.g. a STORAGE finding's "Affected" asset jumps straight to its source). Code already stored by the scan opens instantly; a **Decompile** button triggers a fresh on-demand decompile (`asc`/`jadx` for Android classes) when nothing is stored yet or a second opinion is wanted, sharing its cache with the AI Assistant's `decompile` tool. Each open file gets its own tab so you can compare several classes/functions side by side. Backed by `GET /api/v1/scans/{id}/classes`, `GET /api/v1/scans/{id}/source`, and `POST /api/v1/scans/{id}/decompile`.

### Claude Pro/Max OAuth (no separately-billed API key)

`llm-provider`/`LLM_PROVIDER` also accepts **`claude-oauth`**: authorizes Messages API requests against a Claude Pro/Max subscription instead of a pay-per-token `ANTHROPIC_API_KEY`. Used the same way as any other provider — CLI `--llm --llm-provider claude-oauth`, the web upload form, the AI Assistant provider dropdown, and AI Fix's provider override all accept it.

Sign in once with the bundled subcommand:

```bash
# Interactive (needs a browser on this machine) — same Authorization Code + PKCE flow Claude Code itself uses
java -jar cli/target/malimite-cli.jar claude-login

# Or import an already-completed `claude /login` session (no browser needed here)
java -jar cli/target/malimite-cli.jar claude-login --import

# Or paste a token triplet read from another machine
java -jar cli/target/malimite-cli.jar claude-login --access-token=... --refresh-token=... --expires-at-ms=...
```

Credentials are stored at `~/.malimite/anthropic-oauth.json` and refreshed automatically by whichever consumer uses them (the Java CLI during a scan, or the Python web service for chat/AI Fix) — both the Java `ClaudeOAuthProvider` and Python `agent/anthropic_oauth.py` read/write the same file. In Docker (`deploy/web-compose.yml`) this maps to a dedicated `~/.malimite-docker` mount (not `~/.malimite` directly, since the container runs as a different uid); the container has no browser, so sign in on the **host** first, then run [`sync-claude-oauth.sh`](sync-claude-oauth.sh) to copy the result in — the web UI's "Import from Claude Code CLI" button and `claude-login --import` both auto-detect it. A session this far along from a local `claude /login` can also just be imported directly with `CLAUDE_CODE_CREDENTIALS_PATH` pointed at its credentials file.

---

## Slack bot

Standalone bot using Slack Socket Mode — **no public URL or ngrok required**.

```bash
cd bot/python
cp .env.example .env
# Set SLACK_APP_TOKEN (xapp-...) and SLACK_BOT_TOKEN (xoxb-...)
./run.sh
```

DM the bot an `.ipa`, `.apk` or `.xapk` file → it replies with a severity-sorted summary, HTML report, and SARIF attachment. See [`bot/python/README.md`](bot/python/README.md) for Slack App setup.

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

A learned rule is a lead written by an LLM after reading one function, so it is held to a stricter standard than a catalog rule (`RuleQuality`):

- **Semantic anchor:** every alternative of the regex must name something specific (an API, class or constant). Regexes made only of decompiler vocabulary (`param_1`, `uVar3`, `ulong`, `SoftwareBreakpoint`) are rejected: they match ordinary code.
- **Word boundaries:** short generic words must be delimited. `(?:Runtime|exec)` also matches `execute()` and `Executors`; `Runtime\.getRuntime\(\)\.exec\(` does not.
- **Specificity:** a new rule must not match more than ~3% (at least 3) of the *other* functions of the same app.
- **At scan time:** a learned rule that matches more than 20 distinct functions reports nothing, and learned findings are capped at `MEDIUM` (`MALIMITE_LEARNED_MAX_SEVERITY`, default `MEDIUM`).
- Rules stored by older versions are filtered by the same gates when they are loaded, and a unit test keeps the seeds in `deploy/rules/` clean.

**Absence findings** ("no certificate pinning") that depend on a feature only apply when the app uses it, e.g. pinning is not reported for an app with no networking. When the code contains a bytecode interpreter (VM obfuscation), "no jailbreak/root/Frida/anti-debug found" is reported as `UNKNOWN` in the Assessment (with a caveat on the matching findings), and the VM is listed as its own control.

### DeepSeek models

| Model | Use case |
|-------|----------|
| `deepseek-flash` | Default — DeepSeek-V4.1-Flash, fast, 1M context |
| `deepseek-v4-pro` | DeepSeek-V4-Pro, higher quality analysis |
| `deepseek-v4-flash` | Legacy id for the Flash model — still accepted |
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

## AI Fix

Every finding in the **Vulnerabilities** tab has an **✨ AI Fix** action: it calls the configured LLM to rewrite **Description**, **Evidence**, **Risk** (severity/CVSS), **Proof of Concept**, and **Remediation** for that specific finding, grounded in the finding itself and (when the finding is a `FUNCTION` affected type) the decompiled source code it was found in.

- **Reversible, never destructive.** Rewritten text is stored as `Override*` columns (`OverrideDescription`/`OverrideEvidence`/`OverridePocSteps`/`OverrideRemediation`) — the original scanned fields are **never modified**. Risk reuses the same `OverrideSeverity`/`OverrideCvssScore` columns as manual triage; a per-finding flag (`AiFixSeverityWasAi`) tracks whether the AI (not a human) last wrote them, so clicking **Revert to original** never clobbers a reviewer's own manual triage override.
- **Field selection.** Pick which of Description / Evidence / Risk / PoC / Remediation to rewrite — the rest are left untouched. A field the LLM has nothing better to say about is also left untouched (placeholder text like `...` or `N/A` is dropped).
- **Provider.** Uses the scan's configured LLM provider/model by default, overridable per click — same pattern as the AI Assistant chat's provider dropdown. Shares the server's chat rate limit (`CHAT_RATE_PER_MIN`): both spend the same LLM quota.
- **Everywhere, not just the live UI.** `report.html` and the live Vulnerabilities tab both render the AI-rewritten text when present (falling back to the original), with a small "✨ AI-enhanced" note naming the provider that made the change.
- **API:** `POST /api/v1/scans/{id}/vulnerabilities/{vuln_id}/ai-fix` (body: optional `provider`, `model`, `fields`), `POST .../ai-fix/revert`.

---

## Auto Enhance

The **✨ Auto Enhance** button on the Vulnerabilities tab runs AI Fix across many findings at once instead of one at a time — pick findings from a searchable/filterable table, choose which fields to rewrite, and the server works through them as a background job while you watch live progress in the **Activity Log** tab.

- **Reuses AI Fix exactly.** Each finding goes through the same `finding_fix.fix_finding` call and the same reversible `Override*` columns as the per-finding action — nothing about how a rewrite is stored or reverted changes; Auto Enhance only adds the "run this over N findings" orchestration on top.
- **Server-side job, not a browser loop.** `POST /api/v1/scans/{id}/auto-enhance` starts a background job (`web/app/auto_enhance.py`) that keeps running even if the modal or the browser tab is closed — reopening the Vulnerabilities tab (or the modal) picks the live job back up via polling. The report is regenerated **once** at the end of the run, not once per finding.
- **One job per scan at a time.** Starting a second run while one is active returns `409`; this prevents two jobs racing to write overrides on the same findings.
- **Live Activity Log.** A progress ring, failed count, elapsed-time clock, and a per-finding timeline (status, duration, which fields were actually updated, or the provider's error message) update roughly every 1.5s. **View Details** on any finished item shows the exact rewritten text per field. **View Full Log** lists every past run for the scan, newest first.
- **Cancel Batch.** Findings already being rewritten finish normally (nothing is left half-written); everything still queued is marked `cancelled` and skipped.
- **Retry Finding.** Re-runs one failed or cancelled finding with the run's original provider/model/fields — inside the *same* Activity Log entry rather than starting a new run.
- **Rate limit.** An entire Auto Enhance run counts as **one** hit against the shared `CHAT_RATE_PER_MIN` limit (not one hit per finding); concurrency *within* a run is capped separately by `AUTO_ENHANCE_CONCURRENCY` (default 2 parallel LLM calls).
- **API:** `POST /api/v1/scans/{id}/auto-enhance` (body: `vuln_ids`, optional `provider`/`model`/`fields`) · `GET .../auto-enhance` (active job + history) · `GET .../auto-enhance/jobs/{job_id}` (poll one job) · `POST .../jobs/{job_id}/cancel` · `POST .../jobs/{job_id}/items/{vuln_id}/retry`.

---

## HTML Report

`report.html` is a formal, bilingual (Indonesian/English) Vulnerability Assessment document — not just a technical dashboard — generated as a single self-contained file: cover page, executive summary, risk rating scale, findings (grouped by unique `rule_id`, each with affected assets/evidence/PoC/remediation), MASVS category mapping, a Security Assessment section (and, for Android, an AndroidManifest.xml summary: `debuggable`/`allowBackup`/cleartext traffic/Network Security Config/exported components), a glossary of every abbreviation the report uses (MASVS, MASTG, CVSS, CWE, SLA, LLM, the `MAL-<n>` finding-id prefix, etc.), and an approval sign-off sheet.

- **Bilingual by design.** A language toggle (ID / EN / ID+EN side-by-side) switches every label and heading; finding text sourced from the MASTG catalog or an LLM stays in its original language (English) since those fields accept plain strings, not just the template's `{"id":"…","en":"…"}` bilingual shape.
- **Print/PDF-ready.** The template's own "Print PDF" button opens the browser print dialog with A4 margins and page breaks between sections already set up — no separate PDF export step.
- **Picked by platform automatically.** iOS scans get `core/src/main/resources/report-template/va-report-ios.html`'s layout, Android scans get `va-report-android.html`'s (manifest section, DEX/APK-specific glossary entries); both share the same JSON data contract documented at the top of each file.
- **No administrative fields to fill in.** Client name, document number, classification, and sign-off names render as `—` placeholders (`Prepared by` defaults to "Malimite automated scan") — Malimite has no UI for that metadata today, so a reviewer fills them in after export if the report is going into a formal deliverable.
- Requires a network connection to render with its intended fonts (Google Fonts' IBM Plex Sans/Mono, loaded via `<link>`, not vendored) — falls back to the system sans-serif/monospace stack offline.

---

## Configuration

### CLI flags

```
malimite [OPTIONS] <ipa|apk|xapk>
  -o, --out=<dir>          Output directory
  -g, --ghidra=<dir>       Ghidra install (or env GHIDRA_HOME) — iOS Mach-O + Android arm64 .so
  -j, --jadx=<dir>         JADX install (or env JADX_HOME) — Android DEX/Java
      --sarif              Write findings.sarif
      --html               Write report.html
      --llm                Enable LLM enrichment
      --llm-provider=<x>   openai | claude | claude-oauth | deepseek | ollama
      --llm-mode=<x>       fast | summarize | fast_scan   (Fast Scan, first-party)
                           full | find_vulns | full_scan  (Full Scan, includes 3rd-party)
                           auto_fix                       (first-party reconstruct)
                           offensive                      (first-party + security SDKs; requires --llm)
      --include-package=<p> Extra first-party Java package prefix (repeatable)
      --llm-model=<x>      Override default model per provider
      --max-enrich-functions=<n>
                           Cap functions the LLM enricher inspects (0 = no cap; env MAX_ENRICH_FUNCTIONS)
      --decompiler=<x>     Android decompiler backend: jadx (default) | asc — Droid ASC, on-demand,
                           zero-preprocessing (env MALIMITE_DECOMPILER)
      --asc-home=<dir>     Droid ASC checkout dir — runs `python -m droidasc` (else env ASC_HOME, else PATH)
      --max-asc-classes=<n> Cap classes the ASC backend decompiles (0 = no cap; env MAX_ASC_CLASSES)
      --decompile-threads=<n>
                           Parallel ASC getclass workers (default 8; env DECOMPILE_THREADS)
      --ios-light          iOS only: skip Ghidra, scan strings/imported symbols/plist only (no pseudocode;
                           pseudocode-based rules report "not evaluated"). For binaries too large for
                           Ghidra auto-analysis (env MALIMITE_IOS_LIGHT)
      --assessment / --no-assessment
                           Security-controls Assessment (default: on)
      --fail-on=<severity> Exit 1 if findings ≥ HIGH|MEDIUM|LOW

malimite claude-login [OPTIONS]
                           Sign in with your Claude account (OAuth) for --llm-provider claude-oauth —
                           see "Claude Pro/Max OAuth" below for the three sign-in modes
```

### Environment variables

| Variable | Purpose |
|----------|---------|
| `GHIDRA_HOME` | Ghidra install (iOS Mach-O; Android `lib/arm64-v8a/*.so`) |
| `JADX_HOME` / `JADX_PATH` | JADX install root or binary path (Android DEX) |
| `MALIMITE_LEARNED_RULES` / `MALIMITE_LEARNED_RULES_IOS` | iOS learned-rules JSON (default `~/.malimite/learned_rules.json`) |
| `MALIMITE_LEARNED_RULES_ANDROID` | Android learned-rules JSON (default `~/.malimite/learned_rules_android.json`) |
| `MALIMITE_LEARNED_MAX_SEVERITY` | Highest severity an LLM-learned rule may report (`CRITICAL`…`INFO`, default `MEDIUM`) |
| `LLM_PROVIDER` | `openai` · `claude` · `claude-oauth` (Claude Pro/Max subscription, no API key — see [Claude Pro/Max OAuth](#claude-promax-oauth-no-separately-billed-api-key)) · `deepseek` · `ollama` · `none` |
| `OPENAI_API_KEY` | OpenAI API key |
| `ANTHROPIC_API_KEY` | Anthropic API key (only for `claude`; `claude-oauth` needs no key, it uses `malimite claude-login`'s stored session) |
| `DEEPSEEK_API_KEY` | DeepSeek API key |
| `DEEPSEEK_BASE_URL` | Default `https://api.deepseek.com` |
| `OLLAMA_BASE_URL` | Default `http://localhost:11434` |
| `LLM_MODEL` / `LLM_MAX_TOKENS` | Override provider defaults |
| `MALIMITE_IOS_LIGHT` | iOS only: same as `--ios-light` — skip Ghidra, scan strings/symbols/plist only |
| `ASC_HOME` / `MAX_ASC_CLASSES` / `DECOMPILE_THREADS` / `MALIMITE_DECOMPILER` | Android Droid ASC decompiler backend settings — same as `--asc-home` / `--max-asc-classes` / `--decompile-threads` / `--decompiler` |
| `MAX_ENRICH_FUNCTIONS` | Same as `--max-enrich-functions` |
| `SCAN_DIR` | Web service scan output directory |
| `API_KEY` | Optional `X-Api-Key` for web API |
| `CHAT_RATE_PER_MIN` | Shared rate limit for chat, AI Fix, and Auto Enhance (default 30/min; an Auto Enhance run counts once, not per finding) |
| `AUTO_ENHANCE_CONCURRENCY` | Parallel LLM calls within one Auto Enhance run (default 2) |
| `CLAUDE_CODE_CREDENTIALS_PATH` | Where `claude-login --import` and the web UI's "Import from Claude Code CLI" look for an already-completed `claude /login` session (default `~/.claude/.credentials.json`) |

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
mvn test -pl core,cli                            # 232 tests: Java core + CLI
python -m unittest discover web/tests             # 173 tests: FastAPI web service
# or: cd web && source .venv/bin/activate && pytest tests/
```

Unit tests in `core/` cover IPA/APK validation & extraction, Android manifest/NSC ingest, Assessment scanner, MASTG catalogs, LLM providers (including Claude OAuth), SARIF schema, HTML reporter (triage overrides, AI Fix overrides, unique `rule_id` grouping), and platform-scoped learned-rules persistence. `web/tests/` covers the AI Assistant agent loop/tools, AI Fix endpoints, Auto Enhance (job runner, cancel, retry, routes), triage, Functions tab routes, upload handling, and scan lifecycle. Both suites run on every pull request and on `main`.

---

## Roadmap

See [`PHASES.md`](PHASES.md) for the full development plan. Highlights:

- ✅ Core Ghidra pipeline, MSTG/MASTG scanner, LLM, SARIF/HTML, CI templates
- ✅ Android APK analysis (JADX or Droid ASC for DEX + optional Ghidra arm64 `.so`)
- ✅ Security Assessment mode (PRESENT / PARTIAL / ABSENT / UNKNOWN), aware of bytecode-VM obfuscation
- ✅ AI Assistant: chat over the scan with tools, on-demand ASC / JADX / Ghidra decompilation, Frida hook-target recommendations
- ✅ Functions Explorer: JADX-GUI-style file tree + source viewer for everything a scan decompiled
- ✅ Claude Pro/Max OAuth as an LLM provider — no separately-billed `ANTHROPIC_API_KEY` required
- ✅ iOS light scan mode (`--ios-light`): strings/symbols/plist only, for binaries too large for Ghidra auto-analysis
- ✅ Triage workflow and AI Fix: reviewer overrides and LLM-rewritten finding text, both reversible and both reflected in `report.html`
- ✅ `report.html` rewritten as a formal, bilingual (ID/EN) Vulnerability Assessment document — cover page, risk rating scale, MASVS mapping, approval sheet, glossary, Android manifest summary, print/PDF-ready
- ✅ Auto Enhance: bulk AI Fix as a server-side background job with live Activity Log, Cancel Batch, and per-finding Retry
- ✅ Detection quality: quality gates for LLM-learned rules, relevance preconditions for absence findings
- ✅ Hardened web image: Ghidra 12.0.4, unprivileged user, loopback-only by default, API key + rate limit
- 🔄 Closure items: real-IPA/APK integration test and Python tests on CI, cross-reference REST API
- 🔄 Chat bots (Slack / Telegram / Discord): the standalone Slack bot works; Telegram/Discord only queue a scan. Unifying them on the web API is planned
- 📋 Next major phase: **Observability** (Prometheus metrics, enriched health checks)
- 📋 Future: remaining security hardening, Helm/Kubernetes, enterprise SSO

---

## Credits & license

**Malimite-Core** is a headless reimplementation inspired by [**Malimite**](https://github.com/LaurieWired/Malimite) by [LaurieWired](https://github.com/LaurieWired). Malimite is an iOS and macOS decompiler built on Ghidra with direct Swift/Objective-C support and built-in LLM method translation — if you need an interactive desktop tool, start there.

Key upstream concepts ported (with Swing removed):

- `GhidraProject` → `GhidraRunner`
- `DynamicDecompile` / `FileProcessing` → `MalimiteAnalyzer` / `IpaExtractor`
- `AIBackend` → `LlmEnricher` (+ Claude, DeepSeek, Ollama providers)
- `DecompilerBridge/ghidra/DumpClassData.java` → bundled Ghidra post-script
- `SQLiteDBHandler` → `SqliteStore`

**Built on the shoulders of:**

- [**Ghidra**](https://github.com/NationalSecurityAgency/ghidra) (NSA) — iOS and native-library decompilation
- [**JADX**](https://github.com/skylot/jadx) (skylot) — Android DEX → Java
- [**Droid ASC**](https://pypi.org/project/droidasc/) — on-demand Android decompiler backend, a separate independently released package inspired by [**MG1937/ASC**](https://github.com/MG1937/ASC) (Apache-2.0); builds on [Androguard](https://github.com/androguard/androguard)
- [**OWASP MASTG / MASVS**](https://mas.owasp.org/) — the detection catalogs derive from the Mobile Application Security Testing Guide (CC BY-SA 4.0)
- [**SARIF**](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) (OASIS) — result interchange format

The full list, with licenses and how each is used (bundled, invoked, or derived), is in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

Licensed under the **Apache License 2.0**, consistent with upstream Malimite. See [Malimite LICENSE](https://github.com/LaurieWired/Malimite/blob/main/LICENSE).

---

## Contributing

Issues and pull requests are welcome. Before opening a PR:

1. Run `mvn test -pl core,cli` and, from the repo root, `python -m unittest discover web/tests` (both run on every pull request in CI)
2. Keep changes focused — Malimite-Core favors minimal, headless diffs
3. Credit Malimite when porting additional upstream functionality

**Star [Malimite](https://github.com/LaurieWired/Malimite)** if you find this project useful — and consider starring Malimite-Core too once it's on GitHub.
