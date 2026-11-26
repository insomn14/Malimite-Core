# Dynamic Analysis: ringkasan desain UX (mockup visual)

Status: **mockup untuk review, belum ada kode produk.** Rencana teknis belum disetujui, jadi dokumen ini sengaja singkat.
Mockup interaktif: [`wireframes/index.html`](wireframes/index.html) (buka langsung di browser, tanpa dependency). Screenshot: `wireframes/screenshots/` (1440 dan 1024 px).
Token visual sama dengan `web/index.html` (`--accent #4f46e5`, radius 8/14px, system-ui, nav 52px). Semua teks UI berbahasa Inggris.

## Layar di mockup

| # | Layar | Lokasi di IA | Intinya |
|---|-------|--------------|---------|
| 1 | Devices & Runner | Nav baru **Devices** | Kesehatan runner, daftar device, allowlist, preflight per device. State: healthy, loading, no runner, offline, permission denied |
| 2 | Session launcher + consent gate | Scan detail, tab **Dynamic** | Pilih device, preset probe, mode (manual/guided/automated). Panel plan menampilkan "14 of 23 findings can be verified". Consent modal wajib sebelum start |
| 3 | Live Session console | Mode fokus (tab scan disembunyikan) | Timeline event yang bergerak, tab Traffic/Logs, panel probe on/off, verdict provisional, screenshot ter-blur, Pause capture, **Stop & detach** (`Alt+Shift+X`) |
| 4 | Session review | Tab Dynamic | Daftar session, tile verdict, tabel finding x verdict, kandidat finding `dynamic`, provenance CI |
| 5 | Finding detail + Dynamic Evidence | Tab Vulnerabilities | Badge verdict, bukti (event/flow), Re-test, Override verdict, riwayat verdict |
| 6 | Probe Library | Nav baru **Probes** | Filter, detail, intrusiveness, draft AI "needs review" |
| 7 | Traffic inspector | Sub-view session | Filter/search, nilai sensitif ter-mask, Mark as evidence, replay read-only |
| 8-10 | Compare, AI Assistant (kartu konfirmasi `start_session` / `propose_probe`), HTML report dengan seksi Dynamic Verification | | Pelengkap |
| 11 | Vulnerabilities + eskalasi | Tab Vulnerabilities | Kolom verdict dinamis, filter verdict, "Verify dynamically" per baris dan batch, drawer 3 langkah (Review, Test plan, Authorize) |
| 12-13 | PoC console + PoC results | Mode fokus, lalu tab Dynamic | Checklist langkah PoC, pin evidence, draft PocSteps dengan diff, saran triage |
| 14 | AI agent (mode izin) | Tab AI Assistant, sub-view "Dynamic agent", dan panel di Live console | Plan / Ask / Accept edits / Bypass, tool-call card, safety floor, budget, action log |

## 5 keputusan desain utama

1. **Tab "Dynamic" per scan + dua item nav global (Devices, Probes).** Hasil dynamic selalu milik satu scan, sedangkan runner/device dan katalog probe dipakai lintas scan (sejajar dengan "Learned Rules"). Ditolak: satu halaman "Dynamic" global, karena memisahkan hasil dari finding statisnya. Catatan: scan detail sudah punya 11-12 tab (12 bila mode Offensive), jadi tab Dynamic menambah beban bar tab.
2. **Verdict selalu ikon + teks, tidak hanya warna.** `CONFIRMED` (target), `NOT_REPRODUCED` (slash), `INCONCLUSIVE` (tanda tanya), `NOT_TESTED` (garis putus). Teks `NOT_REPRODUCED` diberi catatan "not proof of safety" supaya reviewer tidak membacanya sebagai "aman".
3. **Keselamatan terlihat di mana-mana.** Chip `REC` global di nav selama session aktif, strip `INTERCEPTING HTTPS` berwarna solid, tombol Stop selalu terlihat tanpa dialog konfirmasi (data sudah tersimpan, jadi aman). Consent modal merekam siapa, kapan, device, dan referensi engagement. Probe intrusiveness High butuh centang tambahan.
4. **Persetujuan AI bukan otorisasi.** Kartu konfirmasi `start_session` memakai pola `chat-confirm` yang sudah ada, tetapi setelah Approve, consent modal tetap muncul. Probe usulan AI hanya jadi *draft*, tidak bisa jalan sebelum direview orang kedua.
5. **Verdict live hanya "provisional"; verdict final dihitung saat session berhenti.** Penguji melihat sinyal secara realtime tanpa mengira itu hasil akhir. Nilai sensitif (token, cookie, PII) ter-mask dan reveal-nya dicatat. Daftar event dibatasi 400 baris di DOM dengan pill "N new, jump to live" saat auto-scroll dijeda.

## Eskalasi PoC, mode izin agent, dan safety floor

- **Eskalasi:** dari baris atau detail finding, "Verify dynamically" membuka drawer 3 langkah. (1) Review: bukti statis dan hipotesis. (2) Test plan: probe terpetakan (nama, intrusiveness, yang diamati), arti tiap verdict, device + preflight, mode Manual/Guided/AI-assisted. (3) Authorize: consent yang tidak bisa dilewati siapa pun. Batch menampilkan antrean finding ke probe, probe bersama hanya dimuat sekali, dan estimasi durasi.
- **Tanpa probe:** tombol disabled dengan alasan ("No probe covers this rule yet") dan tautan "Propose probe with AI". Probe draft AI juga memblokir sampai direview.
- **Hasil:** verdict kembali ke baris Vulnerabilities. "Draft PoC steps" hanya untuk CONFIRMED dan butuh minimal satu event yang di-pin. Hasilnya ditampilkan sebagai diff terhadap PocSteps lama, harus di-accept manusia, dan reversible seperti AI Fix (`OverridePocSteps`). Saran triage tidak pernah otomatis; NOT_REPRODUCED tidak disarankan menjadi false positive.
- **Mode izin agent:** **Plan** (read-only, menghasilkan Plan card), **Ask** (default, tiap aksi non-read minta persetujuan), **Accept edits** (baca + observasi pasif otomatis; ubah device dan probe Medium/High tetap tanya), **Bypass** (semua aksi dalam scope jalan otomatis). Ask ditambahkan sebagai baseline karena Plan card menyebut "run in Ask mode".
- **Tier tool:** Read, Observe, Modify device, Active probe. Status kartu: pending approval, auto-approved, running, done, blocked by safety floor, denied, cancelled, planned.
- **Safety floor (selalu aktif, 8 butir):** (a) consent tetap manusia, (b) scope dikunci ke package scan dan allowlist, (c) Stop agent dan Stop & detach selalu hidup, (d) probe High hanya jika manusia mengaktifkan di launcher, (e) redaksi tetap berlaku, (f) tanpa shell atau JS bebas, probe hash-pinned, (g) budget 40 aksi dan 15 menit, (h) audit log berisi siapa yang menyetujui.
- **Bypass:** butuh dialog konfirmasi + centang, hanya untuk device berlabel lab/emulator, banner merah permanen + chip di nav, turun ke Ask satu klik. Otomatis kembali ke Plan saat device terputus, budget habis, atau consent dicabut.
- **Rule ID di mockup** diambil dari `AndroidVulnerabilityCatalog` (`MASTG-TEST-xxxx`), `VulnerabilityCatalog` (iOS `MSTG-*`), dan `AssessmentScanner` (`ASSESS-*`). Judul, severity, CVSS, dan CWE sama dengan katalog.

## Report: Dynamic Verification dan PoC oleh AI agent (layar 10)

- **Opsi report** (panel di layar 10 dan di Downloads): sertakan seksi dinamis, detail PoC AI, action log, kutipan traffic/event (disamarkan), bahasa ID/EN/Bilingual, dan transkrip chat sebagai opsi terpisah dengan peringatan data sensitif.
- **Draf AI yang belum di-accept manusia tidak pernah tampil sebagai final.** Pengguna memilih eksplisit: dikecualikan (default) atau disertakan dengan label "Unreviewed AI draft" dan watermark di halaman.
- **Label atribusi AI selalu ikut** ("Executed with AI agent assistance", mode izin, reviewer + waktu) dan tidak bisa dimatikan; opsi hanya mengatur kedalaman detail.
- **Lampiran A (AI Agent Activity):** jumlah aksi per tier, aksi yang diblok safety floor (aturan a-h), anggaran, pernyataan transparansi, lalu daftar aksi dengan approver. Sesi Bypass punya kotak merah di cover, seksi dinamis, dan lampiran. Sesi manual hanya menampilkan "Manual session".
- **Consent** tampil di cover dan lembar persetujuan (siapa, waktu, versi pernyataan, catatan scope, baris tanda tangan reviewer).
- **Kompatibilitas:** untuk scan tanpa sesi dinamis, output report harus identik dengan versi sekarang (tanpa seksi, lampiran, atau baris consent baru). Mockup menampilkan ini sebagai skenario "No dynamic analysis".
- **Navigasi:** layar 13 dan 14 punya "Add to report" dan "Preview in report" yang membuka layar 10 pada anchor finding. Cetak/PDF memakai `@page` A4 dan satu halaman per `.rpage`; diverifikasi lewat `page.pdf()` (jumlah halaman PDF sama dengan jumlah halaman report).

## Temuan penting tentang token existing

Beberapa badge existing tidak lolos WCAG AA untuk teks kecil: `badge-running` 2.64:1, `badge-medium` 2.86:1, `badge-done` 3.0:1, `badge-high` 3.95:1. Border `--border` (1.27:1) juga terlalu pucat untuk kontrol interaktif. Mockup memakai nuansa lebih gelap untuk token baru (verdict, intrusiveness, REC, dynamic; semua 4.8:1 atau lebih) dan `--border-strong #8b909a` untuk kontrol. Rekomendasi: perbaiki badge lama dalam PR terpisah. Dark mode tidak ada saat ini dan tidak dirancang di sini.

## Open questions untuk engineering

1. **Verdict final baru ada setelah session.** UI live hanya bisa menampilkan sinyal provisional. Apakah correlation engine bisa mengeluarkan sinyal inkremental per event?
2. **Phase kill-chain existing (ENVIRONMENT/TRANSPORT/SECRETS/SESSION) tidak memuat kategori seperti storage, WebView, atau IPC.** Perlu field `category` terpisah dari `phase` di model probe.
3. **Mode Automated: engine otomasinya belum didefinisikan** (flow file apa, siapa yang menulis). Di mockup hanya placeholder.
4. **Intercept proxy mengalirkan traffic seluruh device.** Apakah runner bisa memfilter per-app dan membuang sisanya? Mockup berasumsi bisa.
5. **Perangkat terputus:** proxy di device bisa tertinggal. Perlu kebijakan pembersihan (reset otomatis, atau peringatan eksplisit seperti di mockup).
6. **Provenance CI belum punya badge di web UI** (PHASES.md 5h.3 menyebut hanya data layer). Layar 4 mengasumsikan badge ini dibuat bersamaan.
7. **Model izin:** dibutuhkan peran terpisah `dynamic:run`, `reveal`, dan `author` (publish probe). Apakah web server punya konsep peran sekarang?
8. **Bypass mode tetap berisiko walau ada floor.** Agent bisa menjalankan serangkaian aksi in-scope yang masing-masing aman tetapi gabungannya merusak (mis. clear data lalu install ulang berulang). Budget membatasi, tetapi apakah perlu rate limit per tier dan daftar aksi destruktif yang selalu minta konfirmasi walau di Bypass?
9. **Hash-pinned probe belum ada di arsitektur.** Floor (f) mengasumsikan runner memverifikasi hash skrip sebelum memuat. Siapa yang menandatangani hash saat probe dipublikasikan?
10. **Floor (b) butuh runner yang menegakkan scope**, bukan hanya UI. Jika hanya UI yang memblok, agent yang memanggil API runner langsung bisa melewatinya.
11. **Shift+Tab untuk memutar mode** membajak navigasi mundur keyboard di composer. Mockup menambah `Alt+M` sebagai alternatif; perlu keputusan apakah Shift+Tab dipertahankan (risiko aksesibilitas).

## Batasan mockup

Data dummy; tidak ada backend. Script Frida hanya placeholder. Tab scan selain Dynamic/Vulnerabilities/AI Assistant tidak bisa diklik. Daftar flow dirender 120 baris (produksi perlu virtual list). Mockup diverifikasi dengan Playwright (lihat laporan akhir).
