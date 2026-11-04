# malimite-ci

Thin HTTP client for driving a `malimite-web` server from a CI/CD pipeline. Uploads an
APK/IPA/XAPK, waits for the scan, and fails the build (non-zero exit) if a finding at or above
`--fail-on` is present.

**Zero third-party dependencies** — stdlib only (`urllib`), so it runs on any CI runner with
Python 3.9+ and no `pip install` step.

## Why this exists instead of relying on the scan's own exit code

- `POST /api/v1/scans`'s returned `exit_code` reflects subprocess success/failure only — never a
  severity policy.
- `malimite-cli.jar`'s own `--fail-on` flag **is not passed through** when the web service runs
  the CLI as a subprocess, so it has no effect via the API even though the flag exists on the CLI.

This script is the one place severity-gating policy lives for anything driving Malimite over the
REST API — it fetches `/vulnerabilities` and computes the gate itself, the same way
`Main.computeExitCode()` does on the CLI side (see `should_fail()`'s docstring-equivalent
comment in `malimite_ci.py` for the exact severity-matching semantics, which intentionally mirror
the Java implementation exactly).

## Usage

```bash
python3 malimite_ci.py \
  --url http://malimite.internal:7070 \
  --api-key "$MALIMITE_API_KEY" \
  --file app-release.apk \
  --fail-on HIGH
```

| Flag | Default | Notes |
|---|---|---|
| `--url` | *(required)* | Base URL of the `malimite-web` server |
| `--api-key` | `$MALIMITE_API_KEY` | Sent as `X-Api-Key`. Required if the server has `API_KEY` set |
| `--file` | *(required)* | Path to the `.ipa`/`.apk`/`.xapk` to scan |
| `--fail-on` | `HIGH` | `NONE`, `LOW`, `MEDIUM`, or `HIGH` — see severity semantics below |
| `--llm-enabled` | off | Enables LLM enrichment for this scan (slower, spends API quota) |
| `--no-assessment` | off | Disables the Security Assessment controls inventory |
| `--timeout` | `1800` | Max seconds to wait for the scan to finish |
| `--poll-interval` | `5` | Seconds between status polls |
| `--json-out` | — | Write a machine-readable summary (`scan_id`, severity counts, verdict) for a later pipeline step |
| `--ci-pipeline-url` | auto-detected | Link to this pipeline run, shown in the web UI (see below) |
| `--ci-commit-sha` | auto-detected | Commit SHA this scan was built from |
| `--ci-triggered-by` | auto-detected | Free-form label for what started this scan |
| `--no-ci-autodetect` | off | Disable CI environment detection entirely |

### CI metadata auto-detection

A scan started by this script is tagged with an optional `ci_pipeline_url`/`ci_commit_sha`/
`ci_triggered_by` (stored in the scan's `meta.json`, returned by `GET /api/v1/scans/{id}`) so it's
distinguishable in the web UI from a manual upload. These are auto-detected from well-known
environment variables — no configuration needed on Bitbucket Pipelines, Jenkins, or GitHub
Actions:

| CI system | Detected from |
|---|---|
| Bitbucket Pipelines | `BITBUCKET_BUILD_NUMBER`, `BITBUCKET_REPO_FULL_NAME`, `BITBUCKET_COMMIT` |
| Jenkins | `JENKINS_URL`/`BUILD_URL`, `GIT_COMMIT` |
| GitHub Actions | `GITHUB_ACTIONS`, `GITHUB_SERVER_URL`, `GITHUB_REPOSITORY`, `GITHUB_RUN_ID`, `GITHUB_SHA` |

Explicit `--ci-*` flags always override auto-detection. `--no-ci-autodetect` disables it entirely
(the scan is then untagged unless `--ci-*` flags are also passed).

### `--fail-on` severity semantics (matches the CLI's `--fail-on` exactly)

| Value | Trips the gate (exit 1) when... |
|---|---|
| `HIGH` | any active finding is `CRITICAL` or `HIGH` |
| `MEDIUM` | any active finding is `CRITICAL`/`HIGH`/`MEDIUM` |
| `LOW` | **any** active finding at all exists, including `INFO` |
| `NONE` | never — always exits 0 |

"Active" excludes findings with `status` `false_positive` or `fixed` (matches
`VulnerabilityRecord.isSuppressed()` on the Java side and `SarifExporter`'s `MALIMITE004` filter)
— `accepted_risk` findings still count, since they're reviewed but not suppressed. A reviewer's
triage override (`effective_severity`) is honored over the original scanner-assigned severity.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed; no finding met `--fail-on` (or `--fail-on NONE`) |
| `1` | Scan completed; a finding at/above `--fail-on` was found — **fail the build** |
| `2` | Usage/configuration error (bad args, file not found) |
| `3` | Could not reach the server, or an HTTP/network error occurred |
| `4` | The scan itself errored server-side, or exceeded `--timeout` while still running |

## Example: Bitbucket Pipelines step

```yaml
- step:
    name: Malimite Security Scan
    script:
      - python3 tools/malimite-ci/malimite_ci.py
          --url "$MALIMITE_URL"
          --api-key "$MALIMITE_API_KEY"
          --file build/outputs/apk/release/app-release.apk
          --fail-on HIGH
          --json-out malimite-result.json
    artifacts:
      - malimite-result.json
```

`MALIMITE_URL` and `MALIMITE_API_KEY` should be repository/workspace variables (`MALIMITE_API_KEY`
marked **Secured**). See [`deploy/EC2_DEPLOYMENT.md`](../../deploy/EC2_DEPLOYMENT.md) for how to
stand up the server this points at.

### When to trigger the scan

The root [`bitbucket-pipelines.yml`](../../bitbucket-pipelines.yml) and [`Jenkinsfile`](../../Jenkinsfile)
templates default to a **release-tags-only** trigger (a tag matching `v*`, not every commit/PR).
This is deliberate: a full scan can take minutes on a large APK/IPA, and the server has a bounded
concurrency budget (`MAX_CONCURRENT_SCANS`, default 3) — scanning every commit across several
teams' repos would compete for those slots and slow down everyone's build feedback loop. Scanning
only release builds trades fast-per-commit feedback for predictable, low server load.

If your team instead wants fast per-PR feedback and has the server headroom for it, trigger on
every push/PR instead (Bitbucket: `pipelines.pull-requests`/`pipelines.branches`; Jenkins: remove
the `when { tag "v*" }` block) — just size `MAX_CONCURRENT_SCANS` and the EC2 instance for the
resulting load (see `deploy/EC2_DEPLOYMENT.md`'s sizing section).

## Running the tests

```bash
cd tools/malimite-ci
python3 -m unittest test_malimite_ci -v
```

24 tests, all network calls mocked at `urllib.request.urlopen` — no live server required. The
severity-gating logic (`should_fail`, `active_findings`, `severity_counts`) is tested directly as
pure functions; the upload → poll → fetch flow is tested with mocked HTTP responses, including
error paths (HTTP error, connection error, scan error state, timeout).

Also runs automatically on every pull request and push to `main` via `.github/workflows/ci.yml`'s
`malimite-ci-client` job.
