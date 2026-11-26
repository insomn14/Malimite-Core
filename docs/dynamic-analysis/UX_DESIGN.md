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
| 8-10 | Compare, AI Assistant (kartu konfirmasi `start_session` / `propose_probe`), bagian HTML report | | Pelengkap |

## 5 keputusan desain utama

1. **Tab "Dynamic" per scan + dua item nav global (Devices, Probes).** Hasil dynamic selalu milik satu scan, sedangkan runner/device dan katalog probe dipakai lintas scan (sejajar dengan "Learned Rules"). Ditolak: satu halaman "Dynamic" global, karena memisahkan hasil dari finding statisnya. Catatan: scan detail sudah punya 11-12 tab (12 bila mode Offensive), jadi tab Dynamic menambah beban bar tab.
2. **Verdict selalu ikon + teks, tidak hanya warna.** `CONFIRMED` (target), `NOT_REPRODUCED` (slash), `INCONCLUSIVE` (tanda tanya), `NOT_TESTED` (garis putus). Teks `NOT_REPRODUCED` diberi catatan "not proof of safety" supaya reviewer tidak membacanya sebagai "aman".
3. **Keselamatan terlihat di mana-mana.** Chip `REC` global di nav selama session aktif, strip `INTERCEPTING HTTPS` berwarna solid, tombol Stop selalu terlihat tanpa dialog konfirmasi (data sudah tersimpan, jadi aman). Consent modal merekam siapa, kapan, device, dan referensi engagement. Probe intrusiveness High butuh centang tambahan.
4. **Persetujuan AI bukan otorisasi.** Kartu konfirmasi `start_session` memakai pola `chat-confirm` yang sudah ada, tetapi setelah Approve, consent modal tetap muncul. Probe usulan AI hanya jadi *draft*, tidak bisa jalan sebelum direview orang kedua.
5. **Verdict live hanya "provisional"; verdict final dihitung saat session berhenti.** Penguji melihat sinyal secara realtime tanpa mengira itu hasil akhir. Nilai sensitif (token, cookie, PII) ter-mask dan reveal-nya dicatat. Daftar event dibatasi 400 baris di DOM dengan pill "N new, jump to live" saat auto-scroll dijeda.

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

## Batasan mockup

Data dummy; tidak ada backend. Script Frida hanya placeholder. Tab scan selain Dynamic/Vulnerabilities/AI Assistant tidak bisa diklik. Daftar flow dirender 120 baris (produksi perlu virtual list). Mockup diverifikasi dengan Playwright (lihat laporan akhir).
