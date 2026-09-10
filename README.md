# SOC Analysis Console (Stateless & PCAP Triage)

Aplikasi web internal untuk analis Security Operations Center (SOC) yang dirancang untuk melakukan triage cepat pada log mentah, mengekstrak indikator kompromi (IoC), pengayaan intelijen ancaman (*Threat Intelligence*) eksternal, serta analisis paket **PCAP/PCAPNG** menggunakan utilitas CLI TShark.

Aplikasi ini bersifat **stateless**:
- Tidak memerlukan database (analisis diproses langsung *in-memory*).
- Tidak memerlukan login / otentikasi akun.
- Otomatis membersihkan berkas capture sementara (*auto-cleanup*) dari direktori `app/temp_pcap/`.

---

## 📁 Struktur Proyek

```text
aplikasisoc/
├── app/
│   ├── __init__.py
│   ├── main.py                  # Entrypoint FastAPI, static files mounting & Jinja2 templates
│   ├── api/
│   │   ├── __init__.py
│   │   └── routes.py            # Endpoint API (/api/parse-log, /api/analyze-pcap, /api/lookup/ioc)
│   ├── services/
│   │   ├── __init__.py
│   │   ├── analyzer.py          # Ekstraksi regex IoC & TI enrichment (AbuseIPDB & VirusTotal)
│   │   └── pcap_analyzer.py     # Modul analisis lalu lintas PCAP via CLI TShark (subprocess)
│   ├── temp_pcap/               # Direktori sementara file PCAP (otomatis dibersihkan)
│   │   └── .gitkeep
│   ├── static/
│   │   ├── css/
│   │   │   └── style.css        # Tema kustom dark mode & aksen cyber-terminal
│   │   └── js/
│   │       └── app.js           # Frontend interaktif, fetch API, render IoC & visualisasi PCAP
│   └── templates/
│       └── index.html           # Halaman dashboard SOC Dark Mode (Tailwind CSS via CDN)
├── requirements.txt             # Dependensi Python
├── .env                         # Konfigurasi kunci API & path TShark
├── .env.example
├── .gitignore
└── README.md
```

---

## 🚀 Fitur Utama

1. **PCAP / PCAPNG Traffic Analyzer (`/api/analyze-pcap`)**:
   - Menerima berkas capture `.pcap` dan `.pcapng` (hingga 25 MB).
   - Ekstraksi kueri **DNS** (`dns.qry.name`).
   - Ekstraksi **HTTP Host dan URI** (`http.host` & `http.uri`).
   - Ringkasan koneksi **TCP/UDP** (Top Conversations & Protocol Breakdown).
   - **Auto-Cleanup**: Menghapus berkas sementara dari `app/temp_pcap/` segera setelah ekstraksi selesai.
   - **Error Handling**: Penanganan otomatis jika TShark belum terinstal atau berkas rusak.

2. **Raw Log & Payload Analyzer (`/api/parse-log`)**:
   - Ekstraksi ketat IPv4 Publik (mengecualikan RFC 1918 dan localhost).
   - Ekstraksi Hashes (SHA-256, SHA-1, MD5), Domains, URLs, dan CVE.
   - Pengayaan asinkron via **AbuseIPDB** (khusus IP publik) dan **VirusTotal** (khusus Hashes).
   - Proteksi ketat: IP privat dilarang keras dikirim ke API publik.

3. **Quick IOC Lookup**:
   - Pengujian instan satu entitas indikator untuk verifikasi cepat.

---

## ⚙️ Cara Menjalankan

### 1. Instalasi Dependensi

```bash
pip install -r requirements.txt
```

### 2. Jalankan Server

```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
*(Atau `python app/main.py`)*

### 3. Akses Dashboard

- **Dashboard:** [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- **Swagger Docs:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
