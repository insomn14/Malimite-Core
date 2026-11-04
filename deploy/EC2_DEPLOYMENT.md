# Deploying Malimite-Core to EC2 (native, systemd)

Guide for running `malimite-web` on a dedicated EC2 instance, reachable from the organization's
CI/CD runners (Bitbucket Pipelines, Jenkins) so every APK/IPA build can be scanned automatically
and reviewed afterward in the web UI.

This mirrors the **exact setup already verified in this session's sandbox** — native systemd
service (not Docker), Ghidra 12.0.4 + JADX installed directly on the host. `deploy/web.Dockerfile`
exists as an alternative but has not been deployment-tested outside this sandbox; this guide
intentionally does not use it.

> **Scope note:** this covers the host/OS/service layer only. It does **not** cover the
> `--fail-on` CI/CD gating logic (that's a separate `malimite-ci` client script, tracked
> separately) or TLS/load-balancer setup (left to your organization's existing ALB/ACM
> conventions — a bare internal HTTP endpoint behind a VPC is assumed below).

---

## 1. Instance sizing

Sized for **moderate volume** (10-50 scans/day, several teams building in parallel).

| | Recommendation | Why |
|---|---|---|
| **Instance type** | `r6i.xlarge` (4 vCPU, 32GB RAM) or `r6i.2xlarge` (8 vCPU, 64GB RAM) if >25 scans/day | RAM-heavy, not CPU-heavy: Ghidra's headless analyzer is the dominant cost per scan |
| **Root volume (OS + app)** | 30GB gp3 | Ghidra install alone is ~850MB; JDK/JADX/app code add a few hundred MB more |
| **Scan data volume** | Separate EBS volume, start at 100GB gp3, resizable live | **One scan can be 1.4GB** (large IPA with many embedded frameworks, see §5) — 50 scans/day with no cleanup fills 100GB in under 2 days. §6 covers automated retention |
| **OS** | Ubuntu 22.04/24.04 LTS | Matches `deploy/web.Dockerfile`'s `python:3.12-slim` base closely enough that package names below are accurate as-is |

### ⚠️ No built-in scan concurrency limit — read before sizing

`web/app/scanner.py`'s `create_scan()` spawns the CLI as a subprocess with **no queue, no
semaphore**. If 5 developers' pipelines all `POST /api/v1/scans` within the same minute, **5
Ghidra headless processes run in parallel**, each with its own JVM heap. This is the #1 reason to
size for RAM headroom rather than assume requests serialize — they don't, today. If pipeline
volume is bursty (e.g. everyone merges before a release freeze), either:
- oversize RAM generously (this guide's `r6i.2xlarge` recommendation already assumes some overlap), or
- have `malimite-ci` (the planned CI client) throttle itself client-side (e.g. a Jenkins/Bitbucket
  concurrency lock on the scan step), since there's no server-side queue to rely on yet.

---

## 2. Security group / network

| Port | Direction | Source | Purpose |
|---|---|---|---|
| 22 | Inbound | Your bastion/VPN CIDR only | SSH admin |
| 7070 | Inbound | CI/CD runner CIDR(s) + reviewer VPN CIDR | Malimite web API + UI |
| 7070 | — | **Never 0.0.0.0/0** | See §4 — `API_KEY` alone is not a substitute for network restriction |
| 443 (optional) | Inbound | Same as 7070 | Only if you terminate TLS on this instance instead of an ALB |

Put the instance in a **private subnet** with no public IP; reach it via VPC peering/Direct
Connect/VPN from CI runners and reviewers' machines, the same way you'd reach an internal Jenkins
or Nexus. Do not expose 7070 to the internet.

---

## 3. Install dependencies

```bash
sudo apt-get update
sudo apt-get install -y \
  openjdk-21-jdk-headless \
  python3.12 python3.12-venv python3-pip \
  curl unzip ca-certificates \
  libharfbuzz0b libfontconfig1 libfreetype6   # Ghidra's analyzers load the JDK font manager even headless
```

> **JDK version matters.** This sandbox's default `java` is JDK 22, which Ghidra's OSGi script
> loader rejects (`osgi.ee=UNKNOWN`) — worked around here via a `GHIDRA_JAVA_HOME` env var pointed
> at a separate JDK 21 install (see `web/app/config.py` / the systemd unit in §7). **On a fresh EC2
> instance, installing `openjdk-21-jdk-headless` as the only JDK avoids needing that workaround at
> all** — simpler for a from-scratch deploy. If you later install a newer JDK too, keep the
> `GHIDRA_JAVA_HOME` override.

### Ghidra 12.0.4 (exact version — do not substitute)

```bash
GHIDRA_VERSION=12.0.4
GHIDRA_DATE=20260303
sudo mkdir -p /opt/malimite
cd /tmp
curl -fL -o ghidra.zip \
  "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip"
sudo unzip -q ghidra.zip -d /opt/malimite
sudo mv "/opt/malimite/ghidra_${GHIDRA_VERSION}_PUBLIC" /opt/malimite/ghidra
rm ghidra.zip
```

**Do not use Ghidra 11.1.2** (rejects the `-enableAnalyzer` flag the scan passes, `Bad argument`)
or **12.1+** (known `DumpClassData.java` post-script regression — class loader change breaks the
"public class == filename" rule). 12.0.4 is the only version verified against this codebase.

### JADX 1.5.1 (Android DEX decompilation)

```bash
cd /tmp
curl -fL -o jadx.zip "https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1.zip"
sudo unzip -q jadx.zip -d /opt/malimite/jadx
rm jadx.zip
sudo chmod +x /opt/malimite/jadx/bin/jadx /opt/malimite/jadx/bin/jadx-gui
```

### Droid ASC (optional — alternate Android decompiler)

Skip unless you specifically want `--decompiler asc`; JADX above is the default and sufficient.

```bash
pipx install droidasc   # needs: sudo apt-get install -y pipx && pipx ensurepath
```

---

## 4. Get the application

Two options — pick based on whether this EC2 instance has outbound internet to Maven Central.

### Option A: download the pre-built release JAR (simpler, no Maven needed on the instance)

```bash
sudo mkdir -p /opt/malimite/app
cd /opt/malimite/app
VERSION=0.3.2   # use the latest tag — check https://github.com/insomn14/Malimite-Core/releases
curl -fL -o malimite-cli.jar \
  "https://github.com/insomn14/Malimite-Core/releases/download/v${VERSION}/malimite-cli-${VERSION}.jar"
curl -fL -o malimite-cli.jar.sha256 \
  "https://github.com/insomn14/Malimite-Core/releases/download/v${VERSION}/malimite-cli-${VERSION}.jar.sha256"
sha256sum -c malimite-cli.jar.sha256   # must print "OK"
```

### Option B: build from source on the instance

```bash
sudo apt-get install -y maven git
git clone https://github.com/insomn14/Malimite-Core.git /opt/malimite/src
cd /opt/malimite/src
mvn -q -DskipTests package -pl core,cli
sudo mkdir -p /opt/malimite/app
sudo cp cli/target/malimite-cli.jar /opt/malimite/app/
```

### Web service (Python) — same for both options

```bash
sudo cp -r /opt/malimite/src/web /opt/malimite/app/web   # if you used Option B
# or, if you used Option A (no git clone): fetch just the web/ directory from the release tag
#   curl -fL "https://github.com/insomn14/Malimite-Core/archive/refs/tags/v${VERSION}.tar.gz" \
#     | tar xz --strip-components=1 -C /tmp/malimite-src && sudo cp -r /tmp/malimite-src/web /opt/malimite/app/web

cd /opt/malimite/app/web
python3.12 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt
```

### Create a dedicated service user

```bash
sudo useradd --system --create-home --home-dir /opt/malimite/home malimite
sudo chown -R malimite:malimite /opt/malimite
```

---

## 5. Scan storage

```bash
# attach + mount the separate EBS volume for scan data, e.g. as /dev/nvme1n1
sudo mkfs.ext4 /dev/nvme1n1
sudo mkdir -p /mnt/malimite-scans
sudo mount /dev/nvme1n1 /mnt/malimite-scans
echo '/dev/nvme1n1  /mnt/malimite-scans  ext4  defaults,nofail  0  2' | sudo tee -a /etc/fstab
sudo chown malimite:malimite /mnt/malimite-scans
```

`SCAN_DIR` (configured in §7) points here. A separate volume means you can grow storage
independently of the root volume without downtime (EBS volume modify → `resize2fs`), and a runaway
scan directory can't fill the OS disk and crash the service.

---

## 6. Automated retention

Malimite-web has built-in retention: set `SCAN_RETENTION_DAYS` in `.env` (already templated in
§7) and the app deletes scan directories older than that on its own — once at startup, then once
a day for as long as the process runs. **Default is `0` (disabled, keep every scan forever)** —
for a CI-triggered deployment generating scans continuously, set it explicitly:

```bash
# in /opt/malimite/app/web/.env
SCAN_RETENTION_DAYS=30
```

Restart the service (`sudo systemctl restart malimite-web`) for a changed value to take effect
immediately; otherwise it's picked up on the next daily sweep regardless. Age is measured from
each scan's `created_at`, and a scan that's currently `queued`/`running` is never deleted out from
under its own in-flight CLI subprocess — it ages out on the next sweep once it finishes. Adjust to
your compliance/audit requirements — if reviewers need longer access to historical scans, raise it
and grow the EBS volume accordingly instead of shortening retention.

### Alternative: external systemd timer

If you want retention decoupled from the app process (e.g. to run at a specific low-traffic hour
rather than "once a day from whenever the service last started"), a systemd timer calling the
same cleanup logic via a plain `find`/`rm -rf` works just as well — the built-in option above is
simpler to operate (no extra unit files) and is what this guide recommends by default.

---

## 7. systemd service for the web app

```bash
sudo tee /opt/malimite/app/web/.env > /dev/null <<'ENV'
SCAN_DIR=/mnt/malimite-scans
GHIDRA_HOME=/opt/malimite/ghidra
CLI_JAR=/opt/malimite/app/malimite-cli.jar

# REQUIRED before exposing this port to anything beyond localhost — see §2/§8.
API_KEY=CHANGE_ME_TO_A_LONG_RANDOM_VALUE

# How many scans run their Ghidra/JADX subprocess at once — see §1's concurrency warning.
# Requests beyond this queue (state stays "queued") rather than being rejected.
MAX_CONCURRENT_SCANS=3
# How many scans may be STARTED per minute, independent of LLM usage — guards against a
# misconfigured pipeline retry loop flooding the queue. 0 disables this limit.
SCAN_RATE_PER_MIN=30
# Delete scan directories older than this many days — see §6. 0 (default) keeps everything.
SCAN_RETENTION_DAYS=30

# Optional LLM provider for enrichment-enabled scans (leave LLM_PROVIDER unset/none to
# skip LLM entirely — the rule-scanner findings covered by the --fail-on gate still work).
# LLM_PROVIDER=deepseek
# DEEPSEEK_API_KEY=
ENV
sudo chown malimite:malimite /opt/malimite/app/web/.env
sudo chmod 600 /opt/malimite/app/web/.env   # contains API_KEY / LLM keys — not world-readable
```

```ini
# /etc/systemd/system/malimite-web.service
[Unit]
Description=Malimite web service (native)
After=network.target

[Service]
Type=simple
User=malimite
WorkingDirectory=/opt/malimite/app/web
Environment=GHIDRA_JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
Environment=PATH=/opt/malimite/home/.local/bin:/usr/local/bin:/usr/bin
Environment=JADX_HOME=/opt/malimite/jadx
ExecStart=/opt/malimite/app/web/.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 7070

# Tune to actual instance RAM — leave the OS some headroom. On r6i.xlarge (32GB) a sensible
# split is ~24G max / ~20G high, matching the ratio this sandbox uses on its 30GB host (14G/12G).
MemoryMax=24G
MemoryHigh=20G
MemorySwapMax=2G
OOMPolicy=continue

Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now malimite-web.service
sudo systemctl status malimite-web.service
journalctl -u malimite-web.service -f   # tail logs while the first scan runs
```

> **`--host 127.0.0.1` is intentional.** The service only listens on localhost; put a reverse
> proxy (nginx) in front for the organization-wide 7070 listener, or front it with an internal ALB.
> This gives you a place to add TLS, request logging, and IP allowlisting independent of the
> Python process. A minimal nginx config:
> ```nginx
> server {
>     listen 7070;
>     location / {
>         proxy_pass http://127.0.0.1:7070;
>         proxy_set_header Host $host;
>         client_max_body_size 500M;   # nginx's own default (1M) is otherwise hit on large IPAs —
>                                       # FastAPI/Starlette itself has no hard upload size limit
>     }
> }
> ```
> (Run uvicorn on an internal-only port like `127.0.0.1:7071` and have nginx listen on 7070 if you
> go this route — adjust `ExecStart` and the proxy_pass target accordingly.)

---

## 8. Access control — do this before pointing any pipeline at the instance

The server logs a startup warning if `API_KEY` is empty: *"anyone who can reach this port can
upload scans, read results and spend this server's LLM quota."* Treat that warning as a hard
blocker for this deployment, not advisory text.

```bash
# generate a strong key
openssl rand -hex 32
```

Put it in `/opt/malimite/app/web/.env`'s `API_KEY=` (already templated in §7) and restart the
service. Every API call (from `malimite-ci`, from reviewers' browsers, from the Web UI itself)
must then send `X-Api-Key: <value>`. Distribute the key to CI systems via their native secrets
store (Bitbucket repository/workspace variables marked **Secured**, Jenkins Credentials) — never
commit it to a pipeline YAML file.

---

## 9. Smoke test after deployment

From a machine that can reach the instance on 7070 (a CI runner, or via VPN):

```bash
export MALIMITE_URL="http://<ec2-private-ip>:7070"
export API_KEY="<the key from §8>"

# 1. Health check — list scans (should be an empty array on a fresh instance)
curl -s -H "X-Api-Key: $API_KEY" "$MALIMITE_URL/api/v1/scans"

# 2. Upload a real APK/IPA and confirm the full pipeline works end to end
curl -s -X POST "$MALIMITE_URL/api/v1/scans" \
  -H "X-Api-Key: $API_KEY" \
  -F "file=@/path/to/some-app.apk" \
  -F "llm_enabled=false"
# → note the returned scan_id, then poll:
curl -s -H "X-Api-Key: $API_KEY" "$MALIMITE_URL/api/v1/scans/<scan_id>"
# wait for "state": "done", then:
curl -s -H "X-Api-Key: $API_KEY" "$MALIMITE_URL/api/v1/scans/<scan_id>/vulnerabilities" | python3 -m json.tool
```

If step 2 reaches `"state": "done"` with findings listed, Ghidra/JADX, the SQLite pipeline, and
the API are all confirmed working end to end on the new instance. Open
`http://<ec2-private-ip>:7070/#/scan/<scan_id>` in a browser (over VPN) to confirm the web UI
renders the same scan for reviewer validation — this is the "scan from CI, validate in the web UI"
workflow this deployment exists to support.

---

## 10. What this guide deliberately leaves open

- **TLS termination** — left to your existing ALB/ACM or nginx+Let's Encrypt conventions; not
  prescribed here since it depends on your organization's certificate management.
- **Multi-instance / autoscaling** — `SCAN_DIR` and the in-memory job registries (Auto Enhance,
  on-demand decompile) are single-host state; this guide assumes one EC2 instance. Scaling beyond
  one instance would need a shared filesystem (EFS) for `SCAN_DIR` at minimum, and is out of scope
  until volume actually requires it.
- **Backups** — EBS snapshots of the scan-data volume are the simplest starting point; not
  configured here since retention policy (§6) already bounds how much there is to back up.

For the pipeline side (what CI actually invokes against this server), see
[`tools/malimite-ci/README.md`](../tools/malimite-ci/README.md) and the "CI/CD integration"
section of the root [`README.md`](../README.md).
