# Plan: tab **Decompiled** (Functions · Strings · Resources · Entry Points)

Mockup interaktif: [`decompiled-mockup.html`](decompiled-mockup.html) — buka di browser. Kontrol di bar atas: Platform (Android/iOS), Viewport (Desktop/Mobile), Layar (Decompiled / Xref dari tab lain), Anotasi (pin bernomor ↔ catatan di bawah frame). Data di mockup adalah contoh dari scan Krom, sebagian nama fiktif.

Semua nomor baris merujuk `web/index.html` per 2026-11-27 (sebelum perubahan apa pun).

## 1. Keputusan & pertanyaan terbuka

| # | Keputusan | Default di plan ini |
|---|---|---|
| D1 | Nama tab induk | **Decompiled** (usulan Anda; selaras dengan `decompiled.zip`). Alternatif: *Explorer* — lebih akurat karena Strings/Resources/Entry Points bukan hasil dekompilasi, tapi kurang spesifik. |
| D2 | Nama sub-menu pertama | **Functions** (sesuai permintaan). Catatan: isinya browser *class* (iOS/Android), bukan fungsi. Kandidat rename: *Code*. |
| D3 | Tile Summary “Classes” dan “Functions” | Digabung jadi satu tile (keduanya sekarang menaut ke tab yang sama, [4734-4735](../../web/index.html)). Tile **Resources** ditambahkan (belum ada). |
| D4 | Panel Cross-refs di Functions | Tampil inline ≥1100px, overlay di bawahnya, sheet penuh di mobile. |
| D5 | Heuristik “App vs Third-party SDK” (Entry Points iOS) | Butuh data tambahan, lihat §6 fase 2. Tanpa data → grup tidak ditampilkan. |
| D6 | Quick filter Strings, palette `Ctrl K` | Opsional, Fase 4. |

## 2. Masalah yang diselesaikan (hasil audit kode + pengecekan di 127.0.0.1:7070)

- 12 tab di satu bar → terpotong di 1024px; empat di antaranya satu keluarga data.
- Lebar halaman melompat saat masuk Functions (`main-wide` hanya untuk tab itu, [3664](../../web/index.html)).
- Empat tab = empat pola berbeda (pencarian live vs submit, pager Prev/Next vs angka, empty state berbeda); Strings & Resources adalah salinan kode ([5361](../../web/index.html), [5462](../../web/index.html)).
- Functions: filter menampilkan nama pendek tanpa path; iOS hanya merender 500 dari 4.908 class; tombol drawer mobile berada ±400px di bawah layar pertama; tree tidak bisa dipakai dengan keyboard; scroll hilang saat pindah tab file; Copy tanpa umpan balik.
- Strings/Resources: pencarian harus disubmit, value terpotong 300px tanpa copy, kolom kosong (Label iOS, `jadx:N` Android).
- Entry Points: baris tidak bisa diklik; 341 dari 346 baris Android adalah simbol native `Global.<symbol>` di 14 library, yang menenggelamkan 5 komponen manifest; fokus keyboard hilang setelah klik filter.
- Navigasi lintas-tab memakai variabel global (`fnPendingOpen`, `resPendingHighlight`) + `history.replaceState` → tidak bisa dibagikan, tidak ada tombol Back.

## 3. Arsitektur informasi & URL

```
#/scan/<id>/decompiled                     → sub terakhir dipakai (localStorage per scan), default functions
#/scan/<id>/decompiled/functions?class=<FQN>
#/scan/<id>/decompiled/strings?q=<teks>&seg=<segment>&hl=<value>
#/scan/<id>/decompiled/resources?q=<teks>&type=<type>&hl=<value>
#/scan/<id>/decompiled/entrypoints?q=<teks>&type=<type>
```

- Nilai query di-`encodeURIComponent`. Nama class memuat `.` dan `$`; pseudo-class native Android juga memuat `/` dan `:` (mis. `native:lib…so/Global`), jadi bagian `?query` harus dipisahkan **sebelum** hash di-split pada `/`.
- Router ([1616-1627](../../web/index.html)) hanya membaca `parts[2]`; ditambah `parts[3]` + parsing query setelah `?`.
- **Redirect legacy** (bookmark pengguna): `#/scan/<id>/functions|strings|resources|entrypoints` → `…/decompiled/<sub>`.
- Satu helper menggantikan semua pola “tinggalkan state lalu `goTab`”:
  `openDecompiled(id, {sub, class, q, type, hl})` → `location.hash = …` (push, jadi Back berfungsi). Klik sub-nav memakai replace.
- Tab bar: `Summary · Vulnerabilities · Assessment · Decompiled · [Offensive] · LLM Findings · AI Assistant · Log · Downloads` (12 → 9). Pill count Decompiled = jumlah class; count per sub ada di sub-nav.

## 4. Inventaris xref — semua yang harus diperbarui

### A. Xref masuk yang **sudah ada** (wajib dimigrasi di Fase 0)

| # | Sumber | Lokasi | Sekarang | Setelah |
|---|---|---|---|---|
| A1 | Summary — tile Classes | [4734](../../web/index.html) | `goTab(id,'functions')` | `openDecompiled(id,{sub:'functions'})`; digabung dengan A2 (D3) |
| A2 | Summary — tile Functions | [4735](../../web/index.html) | `goTab(id,'functions')` | (digabung ke A1) |
| A3 | Summary — tile Strings | [4736](../../web/index.html) | `goTab(id,'strings')` | `…/decompiled/strings` |
| A4 | Summary — tile Entry points | [4737](../../web/index.html) | `goTab(id,'entrypoints')` | `…/decompiled/entrypoints` |
| A5 | Summary — `title="Open ${tabLabel(t)}"` | [4803](../../web/index.html) | label tab lama | “Open Decompiled › Strings” dst. (map label sub-view) |
| A6 | Summary — kartu mini Entry Points (`postSummaryHydrate`) | [4850-4871](../../web/index.html), href [4863](../../web/index.html) | href `#/scan/<id>/entrypoints`; baris tidak bisa diklik | href `…/decompiled/entrypoints`; tiap baris menaut ke class-nya (`…/functions?class=`) |
| A7 | Vulnerabilities — “View in Functions →” | [5911-5913](../../web/index.html), handler [5986-5998](../../web/index.html) | set `fnPendingOpen` + `goTab` | “View in Decompiled › Functions →”, `href` nyata ke `…/functions?class=<FQN>` |
| A8 | Vulnerabilities — “View in Resources →” | [5911](../../web/index.html), handler [5991-5994](../../web/index.html) | set `resPendingHighlight` + `goTab` | “View in Decompiled › Resources →”, `href` ke `…/resources?q=<evidence>&hl=<evidence>` |
| A9 | `fnAffectedLink()` (FUNCTION tanpa class, BINARY) | [5867-5899](../../web/index.html) | `{tab:'functions', target:null}` | `{sub:'functions'}` tanpa `class` (buka sub-view saja) |
| A10 | Light-scan banner (teks) | [3615](../../web/index.html) | “…dari tab Functions atau AI Assistant” | teks + link ke Decompiled › Functions |
| A11 | Empty/not-ready state | [2041](../../web/index.html), [3554](../../web/index.html), [3669-3671](../../web/index.html) | empat label (“Decompiled functions”, “Extracted strings”, “Extracted resources”, “Detected entry points”) | satu panel untuk Decompiled (`tabLabel('decompiled')`) |
| A12 | Definisi tab: `TABS`, `TAB_ICONS`, `TAB_LABELS`, `tabCountHtml`, `tabsForDetail` | [3506-3543](../../web/index.html) | 4 entri + count `strings`/`entrypoints` | 1 entri `decompiled`; count = `class_count`; count sub dihitung di sub-nav |
| A13 | `renderTab` switch + `main-wide` | [3664](../../web/index.html), [3682-3685](../../web/index.html) | 4 case; lebar hanya untuk `functions` | 1 case → shell Decompiled; `main-wide` untuk seluruh tab |
| A14 | `goTab` / hash tab | [3652-3659](../../web/index.html) | `replaceState` ke `#/scan/<id>/<tab>` | dukung `decompiled/<sub>?query` + redirect legacy |
| A15 | Downloads — daftar Raw API | [7860](../../web/index.html) | `/functions /strings /resources /entrypoints` | **tidak berubah** (endpoint REST tetap); hanya pengelompokan label (opsional) |

### B. Xref keluar dari 4 tab (dipertahankan / diperluas)

| # | Sumber | Lokasi | Perilaku |
|---|---|---|---|
| B1 | Functions — “Ask AI Assistant” | [5272-5275](../../web/index.html) | Tetap (prefill `chatSt(id).prefill` → `goTab(id,'assistant')`). Ditambah aksi “Tanya AI” di baris Strings/Resources/Entry Points dengan prefill sejenis. |
| B2 | Functions — tombol “Decompile with JADX/ASC” & tautan AI Assistant untuk iOS | [5236-5244](../../web/index.html) | Tetap. |
| B3 | Functions — titik severity dari `/vulnerabilities` | `fnLoadSeverityMap` [5301](../../web/index.html) | Diperluas: roll-up per folder, marker inline di gutter, daftar di panel Cross-refs. |
| B4 | Functions — `.zip` | [4957](../../web/index.html) | Pindah ke baris sub-nav (hanya aktif di Functions). |

### C. Xref **baru** (dua arah)

| # | Dari → Ke | Data yang dipakai | Tersedia sekarang? |
|---|---|---|---|
| C1 | Entry Points → Functions (klik baris / tombol) | class FQN dari `parseEntryPoint` (komponen Android; method ObjC) | Ya (client-side). Native `.so` tidak punya class → tanpa tombol. |
| C2 | Functions → Entry Points / Findings (panel Cross-refs) | `/entrypoints`, `/vulnerabilities` (`evidence_location`) | Ya (join client-side). |
| C3 | Resources → Vulnerabilities (“n temuan →”) | `/vulnerabilities` dengan `affected_type=RESOURCE` & `evidence` = value | Ya (kebalikan dari A8). |
| C4 | Functions → Resources (komponen manifest) | `fnComponentNameFromEvidence` ([5860](../../web/index.html)) | Ya, hanya komponen Android. |
| C5 | Strings → Functions (chip class) | Android: `label` = nama class **pendek** (mis. `C0014a`) → ambigu | **Perlu backend**: simpan FQN (kolom baru / `label` berisi FQN). iOS: butuh data xref string→fungsi dari native engine; tidak ada sekarang. |
| C6 | Functions → Strings (strings di class ini) | sama dengan C5 | Tergantung C5. |
| C7 | LLM Findings & Offensive → Functions | `f.class_name` / `f.function_name` (kolom [7558-7559](../../web/index.html), chip drawer [7672](../../web/index.html), hook target `_cls`/`_fn` [7200](../../web/index.html)) | Ya, setelah dicek bahwa format nama sama dengan daftar class (normalisasi di Fase 4). |
| C8 | Assessment drawer → Strings/Resources (langkah “Search …” menjadi tautan ber-query) | `assessGuide()` [5616-5631](../../web/index.html) | Ya; kata kunci per kontrol perlu didefinisikan. |
| C9 | AI Assistant: nama class di jawaban → link Decompiled | teks pesan | Opsional (Fase 4). |

### D. Referensi non-UI

| Tempat | Aksi |
|---|---|
| `README.md` [33](../../README.md), [342](../../README.md) (anchor “Functions tab (Functions Explorer)”) | Ubah judul + anchor jadi “Decompiled tab”, perbarui deskripsi & screenshot. |
| `PHASES.md` [499](../../PHASES.md) (baris “Functions Explorer”) | Tambah baris fase ini. |
| Komentar/docstring: `web/app/main.py` [252](../../web/app/main.py), [283](../../web/app/main.py); `web/app/db.py` [745](../../web/app/db.py), [946](../../web/app/db.py); `web/tests/test_functions_routes.py` [22](../../web/tests/test_functions_routes.py), `test_resources_route.py` [17](../../web/tests/test_resources_route.py) | Ganti “Functions tab/Resources tab” → “Decompiled › Functions/Resources”. Hanya komentar. |
| Endpoint REST `/classes /source /functions /strings /resources /entrypoints /decompile /decompiled.zip`; `ApiServer.java`, `ScanController.java` | **Tidak berubah** (dipakai CI & klien lain). |
| Deep link eksternal: `notify.py` [119](../../web/app/notify.py), `tools/malimite-ci/malimite_ci.py`, `deploy/EC2_DEPLOYMENT.md` [338](../../deploy/EC2_DEPLOYMENT.md) | Hanya menaut ke `#/scan/<id>` → tidak terdampak (diverifikasi dengan grep). |
| Bookmark pengguna `#/scan/<id>/functions` dst. | Ditangani redirect legacy (§3). |

## 5. Perubahan per sub-view (detail visual ada di mockup)

| | Sekarang | Baru |
|---|---|---|
| **Functions** | Tree + viewer (sudah JADX-style); filter nama pendek; iOS dipotong 500; drawer mobile di bawah | Filter path penuh + highlight + debounce; chip “Dengan temuan”; roll-up severity per folder; iOS dikelompokkan (App / Swift modules / Third-party / Native) & di-virtualisasi (tanpa cap); breadcrumb klikabel; scroll per tab file; marker temuan inline; panel Cross-refs; keyboard (`role=tree` atau `<details>`); Copy memakai `copyText`; tombol “☰ Browse” di atas viewer (mobile) |
| **Strings** | Submit-only, 4 kolom, Prev/Next | Live search; kolom Value lebar monospace + Wrap; kolom “Where” (class chip Android / alamat+segment iOS); aksi hover Salin/Tanya AI/Buka class; pager bernomor + ukuran halaman; quick filter (opsional) |
| **Resources** | Submit-only, dropdown type | Live search; segmented type dengan count; chip asal-lompatan (✕); chip “n temuan →”; tooltip di Resource & Value |
| **Entry Points** | List datar, tidak interaktif | Grup per tipe (dapat dilipat); baris klikabel → Functions; Native dikelompokkan per library (judul = nama library); iOS App vs SDK (D5); chip jumlah temuan |

## 6. Fase implementasi (PR kecil berurutan)

| Fase | Isi | Hasil/akseptansi | Ukuran |
|---|---|---|---|
| **0 — Fondasi** (perilaku tetap) | Shell `decompiled` + sub-nav yang membungkus 4 tab **tanpa mengubah isi**; URL baru + parsing query; redirect legacy; `openDecompiled()`; migrasi A1–A14; `main-wide` untuk seluruh tab; state per scan (`decSt`) | `grep` tidak lagi menemukan `goTab(...,'functions'\|'strings'\|'resources'\|'entrypoints')` selain tabel redirect; semua baris §4A lolos uji manual; Back bekerja | M |
| **1 — Strings & Resources** | Komponen bersama (toolbar live + `pagerHtml` + panel) menggantikan `loadStrings`/`loadResources`; Value wide+Wrap+Salin; kolom Where; segmented type; chip asal; C3 | Satu implementasi paginasi; tidak ada kolom kosong; pencarian live dengan guard request-seq yang sama | M |
| **2 — Entry Points** | Baris klikabel (C1); grup & Native per library; chip temuan; fokus tidak hilang (update class, bukan re-render kontrol); iOS App/SDK bila data tersedia | Klik baris membuka class; 341 baris Native jadi ≤ jumlah library; hapus CSS lama `.ep-list/.ep-item/.ep-type-*` ([704-721](../../web/index.html)) **setelah** grep memastikan tidak terpakai | M |
| **3 — Functions** | Daftar perbaikan di §5; panel Cross-refs (C2, C4); virtualisasi iOS | iOS menampilkan 4.908 class tanpa “refine your filter”; keyboard penuh; tombol Browse terlihat di layar pertama mobile; tidak ada regresi pada Android 30k class | L |
| **4 — Xref baru & polish** | C5–C9, palette `Ctrl K`, quick filter Strings, backend FQN untuk Strings (jika disetujui) | Tiap xref baru punya sumber data terverifikasi (§4C) | M–L |

Urutan 1–3 bisa dikerjakan paralel setelah Fase 0 (file sama: `web/index.html`, jadi tetap satu penulis per waktu atau pecah per fungsi dengan hati-hati).

## 7. Rencana verifikasi

- **Tidak ada UI test otomatis** di `web/tests` (hanya route Python). Untuk Fase 0 cukup satu pengecekan statis: perintah `grep -nE "goTab\([^)]*'(functions|strings|resources|entrypoints)'" web/index.html` harus kosong; sisanya checklist manual di bawah.
- **Matriks manual** (scan nyata: Android `3d36097d` [346 EP, 65K strings], iOS native `8164bee3` [4.908 class, 125K strings]) × Desktop/Mobile (375×812):
  1. Tiap baris §4A: klik dari sumbernya, pastikan URL baru, target terbuka, Back kembali ke sumber.
  2. Bookmark lama `#/scan/<id>/functions|strings|resources|entrypoints` ter-redirect.
  3. Ganti sub-view dan scan: state per scan tetap, tidak bocor antar scan.
  4. Scan `state != done`, scan kosong (`isEmptyScan`), scan Light lama: pesan benar.
  5. Fokus keyboard bertahan setelah klik filter/pager; `Tab` menjangkau tree.
- **Performa**: tree Android 30k class (sebelumnya sudah dicek), iOS 4,9K class tanpa cap, pencarian live ≤ 100 ms terasa.
- Perbarui test Python hanya jika kontrak API berubah (Fase 4 backend), bukan untuk perubahan UI.

## 8. Risiko

- **Router berbasis hash** memecah `/`; query harus di-encode konsisten (class `$`, `.`).
- **Satu file besar (`web/index.html`, ≈7,9K baris)**: perubahan paralel mudah bentrok → fase dikerjakan berurutan atau per blok fungsi.
- **Memori**: state per scan untuk 4 sub-view (daftar class 30k, halaman strings) harus dibatasi (simpan query/halaman, bukan data).
- **Heuristik App vs SDK** bisa salah → tampilkan sebagai filter yang bisa dimatikan, bukan penyembunyi permanen.
- **C5/C6** butuh perubahan ingest (JADX/native engine) → jangan menjanjikannya di UI sebelum datanya ada.
