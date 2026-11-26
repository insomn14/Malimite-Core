# Malimite-Core — Rencana Dynamic Analysis

> Status: **proposal / belum diimplementasi**. Dokumen ini ditulis berdasarkan pembacaan kode pada branch `claude/quirky-meitner-8wo6z1` (base `main` @ `e2b8b39`).
> Desain UI/UX: lihat `UX_DESIGN.md` dan `wireframes/` di folder yang sama (dikerjakan agent UI/UX terpisah). Dokumen ini adalah kontrak teknis yang menjadi constraint desain tersebut.

---

## 1. Tujuan, non-tujuan, dan prinsip

### 1.1 Masalah yang diselesaikan
Malimite-Core hari ini 100% **static**: Ghidra (iOS) / JADX (Android) → rule MASTG/MSTG → LLM. Akibatnya:

| Keterbatasan static | Dampak sekarang | Yang diberikan dynamic |
|---|---|---|
| Rule berbasis regex menghasilkan *false positive* (mis. `MSTG-STORAGE-*` match string yang tidak pernah dieksekusi) | Reviewer harus triase manual | **Verdict dinamis** per finding: terbukti / tidak terbukti di runtime |
| Kontrol "ABSENT/UNKNOWN" pada Assessment tidak bisa dibuktikan (apalagi bila ada bytecode VM / packer) | `UNKNOWN` dilaporkan apa adanya | Observasi runtime: apakah pinning / root-check / anti-Frida benar-benar ditegakkan |
| Traffic jaringan, isi `SharedPreferences`/Keychain, plaintext sebelum enkripsi tidak terlihat dari kode | Tidak ada bukti eksploitasi | Capture traffic (mitmproxy), hook crypto/storage, diff filesystem |
| Tab **Offensive** + `recommend_hook_targets` hanya menghasilkan *rekomendasi* & zip skrip Frida | User harus menjalankan sendiri di luar Malimite | Malimite menjalankan, merekam, dan menautkan hasilnya ke finding |

### 1.2 Non-tujuan (eksplisit)
- Bukan debugger interaktif / pengganti Frida REPL / objection. Fokus: **sesi terstruktur yang terekam & dapat direproduksi**.
- Bukan fuzzing otomatis atau exploit automation. Probe bersifat observasi; probe "active/bypass" hanya dengan konfirmasi manusia.
- Bukan sandbox malware analysis. Target: aplikasi yang **diotorisasi** untuk diuji.
- Tidak mengganti static pipeline — dynamic adalah lapisan tambahan yang opsional; scan tanpa dynamic harus berperilaku persis seperti sekarang.

### 1.3 Prinsip arsitektur
1. **Additive & opt-in** — tanpa runner terhubung, seluruh fitur tersembunyi/disabled dengan empty-state jelas; tidak ada regresi pada alur scan.
2. **Eksekusi di luar web server** — web container tidak punya adb/USB dan di-bind ke `127.0.0.1`; kode yang mengendalikan device hidup di proses **Runner** terpisah (blast radius terisolasi).
3. **Reuse pola yang sudah ada** — job runner ala `auto_enhance.py`, SSE ala `/chat`, kartu konfirmasi human-in-the-loop ala `propose_finding`, kolom `Source` di tabel `Vulnerabilities`, `regenerate_report`.
4. **Evidence-first** — setiap klaim dinamis menunjuk ke event/flow konkret (id + timestamp + stack), bukan ringkasan LLM.
5. **Aman secara default** — consent gate, allowlist device, redaksi data sensitif, kill-switch, tidak ada "shell bebas" dari web ke device.
6. **Testable tanpa device** — seluruh orkestrasi diuji dengan `FakeBackend`; emulator hanya untuk smoke test terjadwal.

---

## 2. Arsitektur

```
 Browser (SPA)                         Web service (FastAPI, container)                Runner host (host/VM dengan adb/USB)
┌──────────────────┐   REST + SSE    ┌───────────────────────────────────────┐  WS   ┌───────────────────────────────────┐
│ Tab "Dynamic"    │◄───────────────►│ web/app/dynamic/                      │◄─────►│ runner/ (malimite-runner)         │
│ Devices          │                 │  routes.py     REST + SSE             │ (outb.│  ├─ backends/                     │
│ Live console     │                 │  sessions.py   state machine, job reg  │ dari  │  │   android_adb.py  (adb+frida)  │
│ Probe Library    │                 │  runners.py    registry + WS hub       │ runner│  │   ios_frida.py    (usbmux)     │
│ Finding evidence │                 │  store.py      dynamic.sqlite (WAL)    │ ke    │  │   fake.py         (test)       │
└──────────────────┘                 │  correlate.py  rule→probe→verdict      │ web)  │  ├─ frida_host.py  attach/spawn   │
                                     │  findings.py   → Vulnerabilities(src=  │       │  ├─ mitm.py        mitmproxy addon│
   AI Assistant (agent/tools.py) ───►│                dynamic)                │       │  ├─ logcat.py / syslog.py         │
   tool baru + kartu konfirmasi      │  export.py     dynamic_summary.json    │       │  ├─ fsdiff.py                     │
                                     └───────────┬───────────────────────────┘       │  └─ safety.py   allowlist, kill   │
                                                 │ scan_dir/<id>/                    └──────────────┬────────────────────┘
                                                 │  scan.sqlite (Java-owned, existing)              │ USB / adb / wifi
                                                 │  dynamic.sqlite (web-owned, baru)                ▼
                                                 │  dynamic_summary.json  ──► ReportRenderer   Android emulator/device
                                                 │  dyn_artifacts/ (har, png, fsdiff)          iOS jailbroken device
                                                 ▼
                              Java core: HtmlReporter / SarifExporter membaca dynamic_summary.json
```

### 2.1 Keputusan desain & alasannya

| # | Keputusan | Alasan (terikat ke kode yang ada) | Alternatif yang ditolak |
|---|---|---|---|
| A1 | **Runner = proses Python terpisah** (`runner/`), terhubung **outbound** via WebSocket ke web (`/api/v1/runners/connect`, token per runner) | `web.Dockerfile` tidak punya adb/USB, port 7070 loopback-only; runner outbound tidak perlu membuka port di host device & jalan lewat NAT/VPN | Web langsung memanggil `adb` (butuh `--privileged`/USB passthrough di container → memperluas attack surface); runner sebagai HTTP server (perlu expose port + auth dua arah) |
| A2 | **Frida** sebagai mesin instrumentasi utama; **mitmproxy** (addon, mode regular + transparent opsional) untuk traffic | Repo sudah berbicara Frida (tab Offensive, `recommend_hook_targets`, `offensive_phases.py`, kit zip); mitmproxy punya API addon Python → mudah di-stream sebagai event | Xposed/LSPosed (hanya Android, butuh Magisk), Burp (tidak scriptable headless), Objection sebagai dependensi (wrapper tambahan tanpa nilai) |
| A3 | **DB baru `dynamic.sqlite`** milik web (WAL), bukan menambah tabel ke SQLite milik Java | `SqliteStore` (Java) memiliki schema scan; event dinamis bisa puluhan ribu baris/sesi + ditulis konkuren — hindari lock contention & coupling release Java↔Python | Menambah tabel di scan DB (sudah ada precedent `_ensure_triage_columns`, tapi volume event berbeda kelas dengan finding) |
| A4 | **Finding dinamis masuk ke `Vulnerabilities`** dengan `Source='dynamic'` + kolom baru `DynVerdict`, `DynSessionId`, `DynEvidenceRef` (safe-add, pola `_ensure_*_columns`) | Satu-satunya cara agar Triage, AI Fix, Auto Enhance, tab Vulnerabilities, `--fail-on`, SARIF langsung bekerja tanpa jalur kode paralel; `Source='ai_assistant'` sudah jadi precedent | Tabel finding terpisah (duplikasi seluruh pipeline triase/report) |
| A5 | **Report/SARIF membaca `dynamic_summary.json`** (diekspor Python), bukan membaca `dynamic.sqlite` dari Java | `regenerate_report` memanggil `io.malimite.core.ReportRenderer <scan_dir>`; Java cukup parse satu JSON kecil (seperti `scan.json`) → tidak perlu JDBC ke DB kedua | Java membuka `dynamic.sqlite` langsung |
| A6 | **Probe = manifest YAML + skrip JS** di `probes/` (repo root), divalidasi saat load | Probe adalah unit yang dipetakan ke rule/kontrol; manifest memungkinkan UI filter (platform/fase/intrusiveness) dan correlation engine deklaratif | Skrip JS bebas tanpa metadata (tidak bisa dikorelasikan/diaudit) |
| A7 | **Tidak ada endpoint "run arbitrary shell/JS"** dari web ke device. Hanya probe terdaftar (hash-pinned) + parameter tervalidasi | Mencegah web service yang ter-kompromi / prompt injection pada AI Assistant menjadi RCE ke device & host | REPL bebas di UI (dapat ditambahkan nanti sebagai mode "Advanced" terpisah dengan consent tambahan) |
| A8 | **Event streaming: SSE** (web→browser), **WS** (runner↔web) | SPA sudah memakai SSE untuk chat (`StreamingResponse text/event-stream`); tanpa dependensi frontend baru | WebSocket ke browser (tidak ada precedent, perlu auth handling berbeda) |
| A9 | **Platform order: Android emulator dulu**, lalu Android device, lalu iOS | Emulator = reproducible, bisa headless di CI; iOS butuh device jailbroken (tidak bisa di CI) | iOS-first (hambatan setup terbesar) |

### 2.2 Komponen baru & lokasi

| Path | Isi | Bahasa |
|---|---|---|
| `runner/` (paket `malimite_runner`, entrypoint `malimite-runner`) | Backends, Frida host, mitm addon, logcat/syslog, fsdiff, safety | Python 3.10+ (selaras `web/`), dependensi: `frida`, `frida-tools` (opsional), `mitmproxy`, `websockets`, `pyyaml` |
| `probes/` | `catalog.yaml` index + `android/*.yaml+.js`, `ios/*.yaml+.js`, `lib/` (helper JS bersama: redaksi, stack trace, throttle) | YAML + JS (Frida) |
| `web/app/dynamic/` | `routes.py`, `sessions.py`, `runners.py`, `store.py`, `correlate.py`, `findings.py`, `export.py`, `probe_catalog.py`, `models.py` | Python |
| `web/app/agent/tools.py` (modifikasi) | Tool baru (lihat §7) | Python |
| `web/index.html` (modifikasi) | Tab **Dynamic**, halaman **Devices**, komponen live console (implementasi mengikuti `UX_DESIGN.md`) | vanilla JS/CSS |
| `core/.../HtmlReporter.java`, `SarifExporter.java`, `ReportRenderer.java` (modifikasi) | Baca `dynamic_summary.json`; seksi "Dynamic Verification" + properti SARIF | Java |
| `core/src/main/resources/report-template/va-report-*.html` (modifikasi) | Seksi laporan dinamis + badge verdict | HTML |
| `deploy/runner.Dockerfile`, `deploy/web-compose.yml` (profile `dynamic`) | Image runner untuk emulator headless (Linux + KVM) | Docker |
| `tools/malimite-ci/` (modifikasi) | Flag `--dynamic`, gate verdict | Python |

---

## 3. Model data

### 3.1 `dynamic.sqlite` (per scan, `scan_dir/<scan_id>/dynamic.sqlite`, WAL, dibuat lazily)

```sql
dyn_sessions(
  session_id TEXT PK, scan_id TEXT, runner_id TEXT, device_id TEXT, device_label TEXT,
  platform TEXT,                -- ANDROID | IOS
  state TEXT,                   -- created|preparing|running|paused|stopping|done|error|aborted|device_lost
  mode TEXT,                    -- manual | guided | automated
  package TEXT, app_version TEXT, build_sha256 TEXT,   -- sha256 APK/IPA: reproducibility + compare antar build
  probes_json TEXT,             -- [{id, version, sha256, params}]  (hash-pinned)
  options_json TEXT,            -- intercept_traffic, pinning_bypass, fsdiff, screenshots, retention
  consent_json TEXT,            -- {user, ts, statement_version, scope_note}
  created_at INTEGER, started_at INTEGER, finished_at INTEGER, error TEXT,
  ci_pipeline_url TEXT, ci_commit_sha TEXT, ci_triggered_by TEXT   -- reuse provenance existing
)
dyn_events(
  id INTEGER PK, session_id TEXT, seq INTEGER, ts_ms INTEGER,
  source TEXT,                  -- frida|mitm|logcat|fsdiff|ui|runner
  kind TEXT,                    -- namespace.dot: crypto.cipher.init, storage.prefs.write, net.http, file.write, webview.load, intent.recv, detect.root, ...
  probe_id TEXT, severity_hint TEXT, thread TEXT,
  stack_json TEXT, data_json TEXT, redacted INTEGER DEFAULT 1,
  UNIQUE(session_id, seq)
)  -- index (session_id, kind), (session_id, ts_ms)
dyn_flows(
  flow_id TEXT PK, session_id TEXT, seq INTEGER, ts_ms INTEGER,
  method TEXT, scheme TEXT, host TEXT, port INTEGER, path TEXT, status INTEGER,
  req_headers_json TEXT, req_body_ref TEXT, resp_headers_json TEXT, resp_body_ref TEXT,
  tls_pinned INTEGER, cleartext INTEGER, size_req INTEGER, size_resp INTEGER, redacted INTEGER DEFAULT 1
)
dyn_artifacts(artifact_id TEXT PK, session_id TEXT, kind TEXT, -- screenshot|har|fsdiff|logcat|pcap
              path TEXT, sha256 TEXT, size INTEGER, ts_ms INTEGER)
dyn_verdicts(
  id INTEGER PK, session_id TEXT, vuln_id INTEGER NULL,   -- NULL = temuan baru dari dynamic
  rule_id TEXT, verdict TEXT,    -- CONFIRMED|NOT_REPRODUCED|INCONCLUSIVE|NOT_TESTED
  reason TEXT, evidence_refs_json TEXT,  -- [{type:'event'|'flow', id}]
  confidence TEXT                -- HIGH|MEDIUM|LOW
)
```

Body besar (request/response >64 KB, screenshot, fsdiff) disimpan sebagai file di `dyn_artifacts/` dan hanya direferensikan — mengikuti pola scan dir yang sudah ada (`report.html`, `analysis.log`).

### 3.2 Perubahan pada scan DB (Java-owned) — hanya kolom, via safe-add
`Vulnerabilities`: `DynVerdict TEXT`, `DynSessionId TEXT`, `DynEvidenceRef TEXT` (JSON). Ditambahkan oleh `_ensure_dynamic_columns()` di `db.py` (clone pola `_ensure_triage_columns`) **dan** `addColumnIfMissing` di `SqliteStore.java` agar scan baru langsung punya kolom. Semua kolom nullable → scan lama tidak terpengaruh.

### 3.3 Skema event (kontrak runner ↔ web ↔ correlation)
Satu envelope seragam (`schema_version: 1`):
```json
{"session_id":"...","seq":1042,"ts_ms":1760000000123,"source":"frida",
 "kind":"crypto.cipher.init","probe_id":"android.crypto.cipher-trace@1.2.0",
 "thread":"main","stack":["com.example.bank.Vault.encrypt(Vault.java:88)", "..."],
 "data":{"algorithm":"AES/ECB/PKCS5Padding","key_len":16,"key_sha256_8":"a1b2c3d4","iv":null,"mode":"ENCRYPT"},
 "severity_hint":"HIGH"}
```
Aturan: **nilai sensitif tidak pernah ditulis mentah ke `data` secara default** — runner mengganti dengan `{len, sha256_8, preview_masked}`; "reveal" membutuhkan opsi sesi `capture_raw_secrets=true` (consent tambahan) dan tetap ditandai `redacted=0`.

Katalog `kind` v1 (namespace tetap, dapat dikembangkan tanpa breaking): `crypto.*`, `keystore.*`/`keychain.*`, `storage.prefs.*`, `storage.file.*`, `storage.sqlite.*`, `net.http`, `net.tls.pin`, `webview.*`, `ipc.intent.*`/`ipc.urlscheme.*`, `detect.root|jailbreak|frida|debug|emulator`, `clipboard.*`, `log.leak`, `biometric.*`, `runtime.error`.

---

## 4. Probe Library & Correlation Engine

### 4.1 Manifest probe
```yaml
# probes/android/crypto-cipher-trace.yaml
id: android.crypto.cipher-trace
version: 1.2.0
platform: android
title: Trace javax.crypto.Cipher usage
category: CRYPTO              # bucket sama dgn offensive_phases.CAT_TO_PHASE
phase: SECRETS
intrusiveness: passive        # passive | active (mengubah arg/return) | bypass (mematikan proteksi)
tests:                        # mapping ke static
  rules: [MASTG-TEST-0221, MASTG-TEST-0204]    # Android: ID AndroidVulnerabilityCatalog (iOS memakai MSTG-CRYPTO-3, MSTG-CRYPTO-2c, ...)
  assessment_controls: [ASSESS-KEYSTORE]
script: crypto-cipher-trace.js
params: {redact_keys: {type: bool, default: true}, max_events_per_sec: {type: int, default: 50}}
emits: [crypto.cipher.init, crypto.cipher.dofinal]
verdict:                      # deklaratif; dievaluasi correlate.py (tanpa eval kode bebas)
  - when: {kind: crypto.cipher.init, data.algorithm: {matches: "^(DES|RC4|.*/ECB/.*)"}}
    rule: MASTG-TEST-0221
    result: CONFIRMED
    confidence: HIGH
  - when: {none_of_kind: [crypto.cipher.init], session_min_duration_s: 60}
    rule: MASTG-TEST-0221
    result: INCONCLUSIVE      # tidak ada trafik crypto yang terlihat ≠ aman
requires: {frida: ">=16"}
```
Validasi saat load (CI-able): schema JSON, `rules[]` benar-benar ada di catalog, `emits[]` ⊂ katalog `kind`, hash skrip dicatat ke `probes_json` sesi.

### 4.2 Aturan verdict (anti false-assurance)
Ini bagian paling penting secara keamanan-produk: **dynamic hanya bisa membuktikan *presence*, bukan *absence***.
- `CONFIRMED` — event/flow yang memenuhi kondisi `when` ditemukan. Selalu menyertakan `evidence_refs`.
- `NOT_REPRODUCED` — **hanya** boleh jika probe yang relevan aktif **dan** coverage terpenuhi (durasi minimum / flow yang diperlukan dieksekusi, ditandai oleh mode guided/automated). Label UI harus "Not reproduced in this session", **bukan** "safe/fixed".
- `INCONCLUSIVE` — probe aktif tapi coverage tidak cukup, probe crash, atau app terdeteksi anti-instrumentation (`detect.frida` event).
- `NOT_TESTED` — tidak ada probe yang terpetakan ke rule ini / tidak dipilih.
- `NOT_REPRODUCED` **tidak pernah** otomatis mengubah `Status` triase (tidak auto-FP). Hanya menampilkan saran; manusia yang memutuskan (konsisten dengan prinsip confirmation di `propose_finding`/`apply_triage`).
- `CONFIRMED` dapat menaikkan confidence tetapi tidak otomatis menaikkan severity; severity override tetap lewat triase.

### 4.3 Temuan baru dari dynamic
Probe dengan `creates_finding:` (mis. `net.http` cleartext ke host non-loopback, token di log, `storage.file.write` world-readable) → `findings.py` memanggil `insert_vulnerability_manual`-style insert dengan `RuleId='DYN-<probe>-<n>'`, `Source='dynamic'`, `DynVerdict='CONFIRMED'`, dedupe per `(rule, affected_name)` lintas sesi. Evidence = ringkasan event + referensi, PoC steps otomatis dari urutan event (template, bukan LLM).

### 4.4 Kaitan dengan fitur existing
- **`recommend_hook_targets`** → menjadi *planner*: output (symbol, bucket, confidence) dipakai untuk menyarankan probe set + parameter (`class`/`method` target) di Session launcher.
- **Tab Offensive & Frida kit** → skrip `frida_script` dari LLM **tidak** dieksekusi langsung. Jalur: diusulkan sebagai *custom probe* (status `draft`), ditinjau manusia (diff + hash), baru dapat dipilih. Kit zip tetap ada untuk pemakaian manual.
- **Assessment controls** (`ASSESS-SSL-PINNING`, `ASSESS-FRIDA-DETECTION`, dst.) → mendapat kolom opsional "Runtime observation" (mis. pinning *ditegakkan* / *berhasil di-bypass probe X*).

---

## 5. Orkestrasi sesi

### 5.1 State machine
```
created ──start──► preparing ──ready──► running ◄──resume── paused
                       │                  │  └──pause──►────┘
                       │ fail             ├──stop──► stopping ──► done
                       ▼                  ├──device lost──► device_lost ──(reconnect<=60s)──► running | error
                     error                └──runner lost──► aborted (event disimpan s/d seq terakhir)
```
`preparing` = (1) cek consent & allowlist, (2) runner mengunduh APK via URL bertanda tangan umur-pendek, (3) install (`adb install -r -t`), (4) pastikan `frida-server` versi cocok, (5) set proxy device + install CA mitm (jika intercept), (6) snapshot FS "before", (7) spawn app + load probes. Setiap langkah mengirim event `runner` agar UI menampilkan progres (bukan spinner buta).

### 5.2 Mode sesi
| Mode | Siapa yang menjalankan flow aplikasi | Untuk | Kapan tersedia |
|---|---|---|---|
| **manual** | Pentester menggunakan device/emulator sendiri; Malimite merekam | Persona utama | Fase 1 |
| **guided** | Malimite menampilkan checklist flow ("login", "transfer", "logout") + tombol "mark flow done" → coverage terhitung | Verdict `NOT_REPRODUCED` yang bermakna | Fase 3 |
| **automated** | UI automation (UiAutomator2 / `monkey` terbatas, skrip flow yang disimpan) | CI | Fase 6 |

### 5.3 Concurrency & resource
- Satu sesi aktif per device; N sesi per runner (default 1 per device). Registry in-memory seperti `_JOBS` di `auto_enhance.py`, tetapi state sesi dipersist di `dyn_sessions` agar restart web tidak "menghilangkan" sesi (runner melaporkan sesi aktifnya saat `hello` → reconcile).
- Backpressure: runner mem-batch event (≤100 ms / ≤200 event), rate-limit per probe (`max_events_per_sec`), drop-count dilaporkan sebagai event `runner.dropped` (jangan drop diam-diam).
- Retention: `DYNAMIC_RETENTION_DAYS` (ikut `scan_retention_days` bila 0), batas event/sesi (`DYNAMIC_MAX_EVENTS`, default 500k) dengan ring-buffer untuk `logcat`.

---

## 6. API

Semua di bawah `_check_auth` yang sama dengan endpoint lain (`API_KEY`). Prefix `/api/v1`.

| Method & path | Fungsi |
|---|---|
| `GET /dynamic/status` | `{enabled, runners:[...], devices:[...]}` — dasar empty-state UI |
| `POST /dynamic/runners/token` | Buat token registrasi runner (ditampilkan sekali) |
| `WS /dynamic/runners/connect` | Kanal runner (Bearer token) |
| `GET /dynamic/devices` | Device dari semua runner + health (frida version match, root, CA terpasang) |
| `GET /dynamic/probes` / `GET /dynamic/probes/{id}` | Katalog (filter platform/category/intrusiveness) |
| `POST /scans/{id}/dynamic/sessions` | Buat+start sesi. Body: `{device_id, mode, probes[{id,params}], options, consent:{accepted:true, statement_version, scope_note}}`. **Ditolak 400 bila consent tidak ada** |
| `GET /scans/{id}/dynamic/sessions` / `.../{sid}` | Daftar / detail + ringkasan |
| `GET /scans/{id}/dynamic/sessions/{sid}/stream` | **SSE**: event, flow, status, verdict baru. Mendukung `Last-Event-ID` (resume tanpa kehilangan) |
| `POST .../{sid}/stop` · `/pause` · `/resume` | Kontrol; `stop` idempotent & selalu memicu detach + cleanup proxy device |
| `POST .../{sid}/probes` · `DELETE .../{sid}/probes/{pid}` | Load/unload probe saat sesi berjalan |
| `GET .../{sid}/events?kind=&q=&after_seq=&limit=` · `.../flows` · `.../flows/{fid}` | Query historis (keyset pagination `after_seq`) |
| `GET .../{sid}/artifacts/{aid}` | Unduh artefak (HAR, screenshot, fsdiff) |
| `POST .../{sid}/finalize` | Jalankan correlation → tulis verdict + finding dinamis → `regenerate_report` |
| `POST /scans/{id}/vulnerabilities/{vuln_id}/dynamic-verify` | Satu finding → pilih probe terpetakan → buat sesi (UX "Verify dynamically") |
| `GET /scans/{id}/dynamic/compare?a=&b=` | Diff dua sesi (build/versi berbeda): finding yang berubah verdict, host baru, probe event baru |
| `GET /scans/{id}/dynamic/export` | HAR + JSON ringkasan |
| `POST /dynamic/probes/draft` | Simpan probe draf (dari AI/manual) — **tidak** bisa dieksekusi sebelum `approve` manusia |

Hasil `GET /scans/{id}` ditambah `dynamic_session_count`, `dynamic_verdict_counts` (opsional, `null` bila tak ada) agar badge tab muncul tanpa call tambahan; konsisten dengan `vulnerability_counts` di `ScanDetail`.

---

## 7. Integrasi AI Assistant

Semua tool yang **menulis / menyentuh device** memakai `requires_confirmation=True` (mekanisme `tool_confirm_needed` / `awaiting_confirmation` di `loop.py` — tidak perlu infrastruktur baru). Tool baca-saja berjalan langsung.

| Tool | Konfirmasi? | Fungsi |
|---|---|---|
| `dynamic_list_sessions` | tidak | Ringkas sesi scan ini |
| `dynamic_get_events` | tidak | Query event/flow (filter kind, rentang seq; hasil dipotong `chat_tool_cap` dan **data sudah di-redact**) |
| `dynamic_get_verdicts` | tidak | Verdict per finding |
| `dynamic_plan_session` | tidak | Deterministik (seperti `recommend_hook_targets`): usulkan probe set dari finding + assessment terbuka |
| `dynamic_start_session` | **ya** | Menampilkan device, probe, intrusiveness, flag intercept pada kartu konfirmasi; consent tetap dikumpulkan di UI (agen tidak boleh "menyetujui consent atas nama user") |
| `dynamic_propose_probe` | **ya** | Menyimpan **draft** probe (JS + manifest) — tidak mengeksekusi; user wajib review di Probe Library |
| `dynamic_stop_session` | **ya** (ringan) | Stop |

Mitigasi prompt-injection: **konten event/flow (header, body, log aplikasi) adalah data tak tepercaya** — dibungkus `wrap()` seperti output tool lain (`tools.py:wrap`), tidak pernah dijadikan instruksi; tool tulis tidak menerima parameter yang dapat meng-override consent/allowlist.

---

## 8. Integrasi Report, SARIF, CI

- **`dynamic_summary.json`** (ditulis `export.py` saat `finalize`): sesi, device, probe+hash, verdict per rule, hitungan event per kind, host unik, referensi evidence (id + ringkasan ≤ 300 char, tanpa body mentah).
- **HTML report**: seksi baru "Dynamic Verification" (metodologi, device & build hash, coverage, tabel verdict) + badge verdict pada tiap finding; catatan eksplisit "Not reproduced ≠ not vulnerable". Dwibahasa ID/EN mengikuti template existing.
- **SARIF**: `result.properties.dynamicVerdict`, `properties.dynamicSessionId`; temuan `DYN-*` sebagai result biasa (`ruleId` + `tool.driver.rules`). Tidak mengubah `level` otomatis.
- **`--fail-on` / `malimite-ci`**: opsi gate tambahan `--fail-on-confirmed <SEV>` (hanya menghitung finding `DynVerdict=CONFIRMED`) di sisi `tools/malimite-ci` (sama seperti gate severity yang sudah dihitung klien, bukan dipercayakan ke API).
- **CI headless** (Fase 6): `runner` image berisi emulator (KVM) → `malimite-ci --dynamic --flows flows/login.yaml`; hasil + provenance (`ci_*` sudah ada di `ScanMeta`).

---

## 9. Keamanan & kepatuhan

| Risiko | Kontrol |
|---|---|
| Menguji app tanpa otorisasi | **Consent gate** wajib (pernyataan versi-ed, user+timestamp tersimpan di `consent_json`); banner "Interception active" di UI selama sesi; consent masuk laporan |
| Web service ter-kompromi → kontrol device | Runner hanya menerima perintah dari kanal WS terautentikasi, hanya probe **hash-pinned** dari katalog runner-side (runner memverifikasi hash terhadap salinan lokalnya, bukan percaya payload web); tidak ada exec bebas |
| Data sensitif pengguna test (token, PII) tersimpan | Redaksi default di runner (bukan di UI saja), reveal butuh opsi + consent tambahan, retention pendek, `DELETE` scan ikut menghapus `dynamic.sqlite` + `dyn_artifacts/` |
| Traffic intercept bocor ke jaringan lain | mitm bind ke interface device-network saja; CA mitm dibuat per runner, **dihapus dari device saat sesi selesai** (`cleanup` step wajib, tetap dijalankan saat error/abort) |
| Device hilang dengan proxy/CA masih terpasang | Heartbeat; saat reconnect runner menjalankan `reconcile_cleanup`; UI menampilkan peringatan "device may still route traffic through the proxy" |
| Probe jahat / draft AI | Status `draft→approved` oleh manusia, diff & hash ditampilkan, intrusiveness `bypass` perlu konfirmasi kedua; probe approved bersifat immutable (perubahan = versi baru) |
| Stored-XSS di UI dari data traffic | Seluruh payload di-render via `esc()` (SPA sudah punya `esc/escAttr`); test khusus payload `<script>` di header/body/log |
| Supply chain (frida/mitmproxy) | Pin versi di `runner/requirements.txt`, entry di `THIRD_PARTY_NOTICES.md` (frida: wxWindows Library Licence 3.1; mitmproxy: MIT — **periksa ulang kompatibilitas lisensi dengan Apache-2.0 sebelum bundling**; default: tidak dibundel, dipasang user) |

---

## 10. Strategi pengujian

| Level | Isi | Di CI? |
|---|---|---|
| Unit (`web/tests/test_dynamic_*.py`, stdlib `unittest` seperti suite sekarang) | state machine, correlate (tabel verdict), redaksi, store/keyset pagination, validasi manifest probe, consent gate (400 tanpa consent), authz | ✅ |
| Kontrak runner↔web | `FakeBackend` memutar rekaman event (`tests/fixtures/*.jsonl`) lewat WS sungguhan; assert SSE order, resume `Last-Event-ID`, device_lost, runner_lost | ✅ |
| Java (`core/src/test`) | `HtmlReporter`/`SarifExporter` dengan `dynamic_summary.json` fixture; scan **tanpa** file itu harus byte-identik output lama (regression guard) | ✅ |
| Keamanan | payload XSS pada event/flow; tool AI tulis tak bisa jalan tanpa konfirmasi; runner menolak probe dengan hash tak cocok | ✅ |
| Probe lint | semua manifest valid; rule id ada di catalog; skrip JS lolos `node --check` | ✅ |
| E2E emulator | APK uji sederhana (repo `tests/fixtures/vuln-app/`: ECB crypto, plaintext prefs, cleartext HTTP) → expected verdict CONFIRMED | ⏱ nightly (runner KVM), bukan per-PR |
| Manual / UX | 3–5 skenario usability dari `UX_DESIGN.md` | per milestone |

Catatan jujur: seperti README akui untuk scan nyata, E2E dengan emulator **tidak** berjalan per-PR (butuh KVM); suite per-PR membuktikan orkestrasi, bukan perilaku Frida sebenarnya — itu hanya terbukti di job nightly.

---

## 11. Roadmap bertahap

Estimasi kasar untuk 1 engineer penuh-waktu familiar dengan codebase (rentang, bukan komitmen). Tiap fase menghasilkan sesuatu yang bisa dipakai & di-merge sendiri (feature-flag `DYNAMIC_ENABLED`, default off).

### Fase D0 — Fondasi & kontrak (≈1 minggu)
- Finalisasi `UX_DESIGN.md` (review bersama), ADR untuk A1–A9.
- Definisi skema event v1, manifest probe (JSON Schema), protokol WS runner↔web (dokumen `docs/dynamic-analysis/PROTOCOL.md`).
- Skeleton: `web/app/dynamic/` (models, store, flag), `runner/` (paket kosong + `FakeBackend`), migrasi `_ensure_dynamic_columns`.
- **Selesai bila**: `GET /dynamic/status` → `{enabled:false}`; tab Dynamic tersembunyi; seluruh test existing hijau; scan lama identik.

### Fase D1 — Android MVP: sesi manual + Frida probes (≈3–4 minggu)
| # | Task | Output |
|---|---|---|
| 1.1 | `runner`: koneksi WS + token, `android_adb` backend (list device, install, start frida-server, spawn/attach) | Device muncul di Devices |
| 1.2 | `frida_host`: load probe hash-pinned, relay pesan → event envelope, redaksi di runner | Event masuk web |
| 1.3 | Probe awal (pasif): `crypto-cipher-trace`, `prefs-write-trace`, `file-write-trace`, `webview-load`, `intent-recv`, `detect-root/frida` (observe-only) | 6 probe + lint |
| 1.4 | `sessions.py` state machine + persist + reconcile; `routes.py` REST + SSE (resume) | API |
| 1.5 | UI: Devices, Session launcher + consent gate, Live console (timeline + filter + stop), review sesi | UX_DESIGN §layar 1–4 |
| 1.6 | Test: unit + kontrak `FakeBackend`; E2E emulator manual | CI hijau |
- **Selesai bila**: pentester dapat memilih emulator, memulai sesi manual pada APK dari scan, melihat event live, menghentikan sesi, dan membuka kembali hasilnya setelah restart web.

### Fase D2 — Traffic capture (≈2–3 minggu)
- `mitm.py` (addon → event/flow ke runner), setup proxy + CA device (Android user-CA + opsi system-CA untuk emulator rootable) **dengan cleanup terjamin**.
- Probe `net-pinning-observe` (pasif: deteksi pinning) dan `net-pinning-bypass` (**intrusiveness=bypass**, konfirmasi ganda) — memakai pengetahuan dari `ASSESS-SSL-PINNING`.
- UI: Traffic inspector (list virtualized, detail, redaksi + reveal, "mark as evidence").
- Finding dinamis pertama: cleartext HTTP, token di URL, header sensitif tanpa TLS.

### Fase D3 — Korelasi, verdict, report (≈3 minggu)
- `correlate.py` (declarative verdict), `findings.py` (`Source='dynamic'`), kolom `Dyn*`, `finalize`.
- UI: verdict badge + "Dynamic Evidence" pada finding, tombol **Verify dynamically** & **Re-test**, mode **guided** (checklist coverage).
- `dynamic_summary.json` + perubahan Java (`HtmlReporter`, `SarifExporter`, template) + regression test byte-identik tanpa dynamic.
- **Selesai bila**: satu finding crypto statis (mis. `MASTG-TEST-0221`) berubah menjadi `CONFIRMED` dengan bukti event, tampil di report HTML & SARIF.

### Fase D4 — AI Assistant (≈1–2 minggu)
- Tool §7 + kartu konfirmasi baru (device/probe/intrusiveness); `dynamic_plan_session` dari `recommend_hook_targets`.
- Probe draft dari LLM → review UI (diff, hash, approve).
- Evaluasi prompt-injection (event berisi "ignore previous instructions…") sebagai test.

### Fase D5 — iOS (≈3–4 minggu, risiko tertinggi)
- Backend `ios_frida` (usbmux/`frida-server` pada device jailbroken; Corellium sebagai opsional kemudian), probe: Keychain, `NSUserDefaults`, `NSURLSession` trust evaluation, jailbreak detection.
- Cakupan lebih sempit dari Android pada rilis pertama; dokumentasikan secara jujur.

### Fase D6 — CI/Automation & compare (≈2–3 minggu)
- `deploy/runner.Dockerfile` (emulator headless), mode **automated** (flow YAML via UiAutomator2), `malimite-ci --dynamic`, gate `--fail-on-confirmed`.
- Session compare (antar build), job nightly E2E.

### Fase D7 — Hardening & observability (paralel dengan Phase 6/7 di `PHASES.md`)
- Metrik (sesi aktif, event/s, drop rate, runner heartbeat), retention, audit log consent, load test 500k event, pen-test internal terhadap runner channel.

### Ringkasan dependensi
`D0 → D1 → {D2, D4 (setelah D3)}`; `D3` butuh `D1`(+`D2` untuk finding jaringan); `D5` independen setelah `D1` kontrak stabil; `D6` butuh `D3`.

---

## 12. Daftar file yang akan disentuh (perkiraan)

Baru: `runner/**`, `probes/**`, `web/app/dynamic/**`, `web/tests/test_dynamic_*.py`, `deploy/runner.Dockerfile`, `docs/dynamic-analysis/{PROTOCOL,ADR}.md`, `tests/fixtures/vuln-app/**`.
Modifikasi: `web/app/main.py` (include router, `ScanDetail` field, delete scan ikut hapus dynamic), `web/app/db.py` (`_ensure_dynamic_columns`, query verdict), `web/app/models.py`, `web/app/config.py` (`DYNAMIC_ENABLED`, retention, batas), `web/app/agent/tools.py` (+ `loop.py` hanya jika kartu konfirmasi perlu field tambahan), `web/index.html` (tab, halaman, komponen), `core/.../{HtmlReporter,SarifExporter,ReportRenderer,SqliteStore}.java`, `core/.../report-template/*.html`, `tools/malimite-ci/malimite_ci.py`, `README.md`, `PHASES.md` (tambah Phase 9 "Dynamic Analysis" — nomor menyesuaikan), `THIRD_PARTY_NOTICES.md`, `.github/workflows/ci.yml` (job unit `runner/` + nightly).

---

## 13. Risiko utama

| Risiko | Dampak | Mitigasi |
|---|---|---|
| Anti-instrumentation pada app target (RASP/Frida detection) membuat probe tidak stabil | verdict `INCONCLUSIVE` banyak | Deteksi & laporkan eksplisit (`detect.frida` event); tampilkan kapan hasil tak dapat dipercaya; jangan klaim bypass RASP komersial (selaras catatan di `assessment_catalog`) |
| Fragmentasi Android/Frida versi | Setup device rapuh | Device health check + auto-match frida-server; matriks versi terdukung terdokumentasi |
| UI SPA satu-file 7.5k baris makin besar | Maintainability | Komponen dynamic ditulis modular di blok terpisah; pertimbangkan memecah `index.html` jadi ES modules **hanya** jika disetujui (di luar scope ini) |
| Volume event membebani browser/SQLite | Lag/OOM | Batching, rate-limit probe, virtualized list, ring buffer, keyset pagination |
| Lisensi frida/mitmproxy | Distribusi | Tidak dibundel; lisensi diverifikasi sebelum D1 merge |
| False assurance ("not reproduced" dibaca "aman") | Risiko produk | §4.2: label, coverage gating, tidak pernah auto-FP, disclaimer di report |
| Scope creep ke "full pentest framework" | Jadwal | §1.2 non-tujuan; backlog terpisah |

---

## 14. Keputusan yang masih perlu dari Anda

1. **Target platform rilis pertama**: Android emulator saja (rekomendasi, D1–D4) lalu iOS (D5), atau iOS sejak awal?
2. **Model deployment runner**: runner di host yang sama dengan web (mode "local", paling sederhana) vs host terpisah (lebih aman, lebih rumit). Rencana ini mendukung keduanya lewat WS; mana yang jadi *default doc*?
3. **Multi-user**: apakah web dipakai tim (butuh per-user consent/audit, kini hanya satu `API_KEY` global)? Mempengaruhi D7.
4. **Lisensi/distribusi**: boleh mem-bundle frida/mitmproxy di image Docker, atau hanya instruksi instalasi?
5. **Corellium / device farm** di roadmap atau di luar scope?
