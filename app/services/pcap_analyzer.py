"""
PCAP/PCAPNG Traffic Analysis Service
Modul analisis lalu lintas jaringan PCAP/PCAPNG menggunakan utilitas CLI TShark (Wireshark)
via modul subprocess Python.

Mengekstrak informasi esensial:
1. Daftar kueri DNS (dns.qry.name)
2. Daftar HTTP Host dan URI (http.host dan http.uri)
3. Ringkasan & statistik koneksi TCP/UDP utama (Top Conversations & Protocol Breakdown)

Fitur:
- Deteksi otomatis path instalasi binary TShark di berbagai sistem operasi.
- Error handling lengkap jika TShark belum terpasang atau CLI gagal.
- Pemrosesan asinkron (asyncio.to_thread) agar non-blocking pada server FastAPI.
- Pembersihan file temporary otomatis (auto-cleanup).
- Generator laporan teks naratif terstruktur bergaya CLI / Terminal untuk analis SOC.
"""

import os
import shutil
import asyncio
import subprocess
from pathlib import Path
from collections import Counter
from typing import Dict, List, Any, Optional, Tuple

class TSharkNotFoundError(Exception):
    """Dinaikkan jika binary CLI TShark tidak ditemukan di sistem operasi."""
    pass

class TSharkExecutionError(Exception):
    """Dinaikkan jika eksekusi CLI TShark menghasilkan kesalahan atau exit code bukan 0."""
    pass

def find_tshark_binary() -> str:
    """
    Mendeteksi path binary CLI tshark di sistem:
    1. Memeriksa environment variable TSHARK_PATH dari .env
    2. Memeriksa system PATH melalui shutil.which
    3. Memeriksa lokasi instalasi standar Wireshark di Windows & Linux
    """
    # 1. Cek environment variable
    custom_path = os.getenv("TSHARK_PATH", "").strip()
    if custom_path and os.path.isfile(custom_path):
        return custom_path

    # 2. Cek system PATH
    system_path = shutil.which("tshark")
    if system_path:
        return system_path

    # 3. Cek lokasi instalasi default Windows
    windows_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Wireshark\tshark.exe")
    ]
    for p in windows_paths:
        if os.path.isfile(p):
            return p

    # 4. Cek lokasi instalasi default Linux / Unix / macOS
    nix_paths = [
        "/usr/bin/tshark",
        "/usr/local/bin/tshark",
        "/opt/homebrew/bin/tshark"
    ]
    for p in nix_paths:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p

    raise TSharkNotFoundError(
        "Utilitas CLI TShark (Wireshark) tidak ditemukan pada sistem operasi. "
        "Pastikan Wireshark/TShark telah terpasang di lokasi standar (contoh: C:\\Program Files\\Wireshark\\tshark.exe) "
        "atau daftarkan direktori binary TShark ke dalam System PATH."
    )

def _extract_pcap_sync(pcap_path: Path, tshark_bin: str, timeout_seconds: int = 40) -> Dict[str, Any]:
    """
    Eksekusi satu pass ekstraksi TShark secara synchronous dengan timeout.
    Mengekstrak DNS queries, HTTP Host/URI, dan koneksi TCP/UDP dalam format tab-delimited fields.
    """
    if not pcap_path.exists():
        raise FileNotFoundError(f"File PCAP tidak ditemukan di path: {pcap_path}")

    # Perintah TShark satu lintasan (single pass) cepat
    cmd = [
        tshark_bin,
        "-r", str(pcap_path),
        "-n",  # Matikan resolusi nama network agar ekstraksi berjalan sangat cepat
        "-T", "fields",
        "-E", "separator=\t",
        "-E", "header=n",
        "-E", "occurrence=f",
        "-e", "_ws.col.Protocol",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "dns.qry.name",
        "-e", "http.host",
        "-e", "http.request.method",
        "-e", "http.request.uri"
    ]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False
        )
    except subprocess.TimeoutExpired:
        raise TSharkExecutionError(
            f"Waktu eksekusi TShark melebihi batas toleransi ({timeout_seconds} detik). "
            "File PCAP mungkin terlalu besar atau rusak."
        )
    except Exception as exc:
        raise TSharkExecutionError(f"Terjadi kegagalan saat menjalankan proses TShark CLI: {str(exc)}")

    if proc.returncode != 0 and not proc.stdout.strip():
        stderr_msg = proc.stderr.strip() or "Unknown TShark error"
        raise TSharkExecutionError(f"TShark CLI mengembalikan error (code {proc.returncode}): {stderr_msg}")

    # Parsing output TShark
    dns_counter: Counter = Counter()
    http_counter: Counter = Counter()
    conversation_counter: Counter = Counter()
    protocol_counter: Counter = Counter()
    src_ip_counter: Counter = Counter()
    dst_ip_counter: Counter = Counter()

    total_packets = 0

    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        total_packets += 1
        fields = line.split("\t")
        col_count = len(fields)

        proto = fields[0].strip() if col_count > 0 else "UNKNOWN"
        src_ip = fields[1].strip() if col_count > 1 else ""
        dst_ip = fields[2].strip() if col_count > 2 else ""
        tcp_sport = fields[3].strip() if col_count > 3 else ""
        tcp_dport = fields[4].strip() if col_count > 4 else ""
        udp_sport = fields[5].strip() if col_count > 5 else ""
        udp_dport = fields[6].strip() if col_count > 6 else ""
        dns_query = fields[7].strip() if col_count > 7 else ""
        http_host = fields[8].strip() if col_count > 8 else ""
        http_method = fields[9].strip() if col_count > 9 else ""
        http_uri = fields[10].strip() if col_count > 10 else ""

        # 1. Protokol & Counter IP
        if proto:
            protocol_counter[proto] += 1
        if src_ip:
            src_ip_counter[src_ip] += 1
        if dst_ip:
            dst_ip_counter[dst_ip] += 1

        # 2. Analisis Kueri DNS
        if dns_query:
            for q in dns_query.split(","):
                q_clean = q.strip().lower().rstrip(".")
                if q_clean:
                    dns_counter[q_clean] += 1

        # 3. Analisis HTTP Requests
        if http_host or http_uri:
            method = http_method.upper() if http_method else "GET"
            host = http_host.lower() if http_host else "UNKNOWN_HOST"
            uri = http_uri if http_uri else "/"
            http_counter[(method, host, uri)] += 1

        # 4. Ringkasan Koneksi TCP / UDP
        sport = tcp_sport or udp_sport
        dport = tcp_dport or udp_dport
        conn_proto = "TCP" if tcp_sport or tcp_dport else ("UDP" if udp_sport or udp_dport else proto)

        if src_ip and dst_ip and sport and dport:
            conv_key = (src_ip, sport, dst_ip, dport, conn_proto)
            conversation_counter[conv_key] += 1

    # Format DNS Queries
    dns_queries_list = [
        {"query": query, "frequency": count}
        for query, count in dns_counter.most_common(50)
    ]

    # Format HTTP Requests
    http_requests_list = [
        {
            "method": method,
            "host": host,
            "uri": uri,
            "full_url": f"http://{host}{uri}" if uri.startswith("/") else f"http://{host}/{uri}",
            "frequency": count
        }
        for (method, host, uri), count in http_counter.most_common(50)
    ]

    # Format Top Conversations
    top_conversations_list = [
        {
            "src_ip": s_ip,
            "src_port": s_port,
            "dst_ip": d_ip,
            "dst_port": d_port,
            "protocol": p_type,
            "packet_count": count
        }
        for (s_ip, s_port, d_ip, d_port, p_type), count in conversation_counter.most_common(30)
    ]

    return {
        "summary": {
            "total_packets_parsed": total_packets,
            "unique_dns_queries_count": len(dns_counter),
            "unique_http_requests_count": len(http_counter),
            "unique_conversations_count": len(conversation_counter),
            "top_protocols": dict(protocol_counter.most_common(8)),
            "top_source_ips": dict(src_ip_counter.most_common(5)),
            "top_destination_ips": dict(dst_ip_counter.most_common(5))
        },
        "dns_queries": dns_queries_list,
        "http_requests": http_requests_list,
        "connections": top_conversations_list
    }

async def analyze_pcap_file(pcap_path: Path) -> Dict[str, Any]:
    """
    Fungsi asinkron utama untuk menganalisis file PCAP.
    Menjalankan proses ekstraksi CLI TShark di thread worker terpisah (non-blocking).
    """
    tshark_bin = find_tshark_binary()
    return await asyncio.to_thread(_extract_pcap_sync, pcap_path, tshark_bin)


# ==============================================================================
# CLI / TERMINAL REPORT FORMATTER
# ==============================================================================

def format_file_size(size_bytes: int) -> str:
    """Format ukuran file byte ke representasi yang ramah pembaca (Bytes, KB, MB)."""
    if size_bytes < 1024:
        return f"{size_bytes} Bytes"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB ({size_bytes:,} bytes)"
    else:
        return f"{size_bytes / (1024 * 1024):.2f} MB ({size_bytes:,} bytes)"

def format_pcap_cli_report(pcap_data: Dict[str, Any], filename: str, file_size_bytes: int) -> str:
    """
    Memformat data hasil ekstraksi TShark menjadi laporan teks terstruktur bergaya CLI/Terminal
    yang ringkas, bersih, dan langsung dapat dianalisis oleh analis SOC.
    """
    summary = pcap_data.get("summary", {})
    dns_queries = pcap_data.get("dns_queries", [])
    http_requests = pcap_data.get("http_requests", [])
    connections = pcap_data.get("connections", [])

    lines = []
    divider_major = "=" * 80
    divider_minor = "-" * 80

    lines.append(divider_major)
    lines.append("  [+] SOC TRAFFIC TRIAGE REPORT // TSHARK CAPTURE ANALYSIS")
    lines.append(divider_major)
    lines.append("")

    # 1. INFORMASI BERKAS
    lines.append("[-] INFORMASI BERKAS")
    lines.append(divider_minor)
    lines.append(f"Nama File          : {filename}")
    lines.append(f"Ukuran File        : {format_file_size(file_size_bytes)}")
    lines.append(f"Engine Analisis    : TShark CLI (Single-Pass Dissector)")
    lines.append("")

    # 2. RINGKASAN LALU LINTAS
    lines.append("[-] RINGKASAN LALU LINTAS")
    lines.append(divider_minor)
    total_packets = summary.get("total_packets_parsed", 0)
    lines.append(f"Total Paket        : {total_packets:,} paket")

    # Protokol dominan
    protocols = summary.get("top_protocols", {})
    if protocols:
        proto_str = ", ".join([f"{p} ({count:,})" for p, count in protocols.items()])
        lines.append(f"Protokol Dominan   : {proto_str}")
    else:
        lines.append("Protokol Dominan   : Tidak terdeteksi")

    # Top Sumber & Tujuan
    src_ips = summary.get("top_source_ips", {})
    if src_ips:
        src_str = ", ".join([f"{ip} ({cnt:,} pkts)" for ip, cnt in src_ips.items()])
        lines.append(f"Top Sumber (Src IP): {src_str}")
    else:
        lines.append("Top Sumber (Src IP): -")

    dst_ips = summary.get("top_destination_ips", {})
    if dst_ips:
        dst_str = ", ".join([f"{ip} ({cnt:,} pkts)" for ip, cnt in dst_ips.items()])
        lines.append(f"Top Tujuan (Dst IP): {dst_str}")
    else:
        lines.append("Top Tujuan (Dst IP): -")

    lines.append(f"Koneksi Aktif      : {summary.get('unique_conversations_count', 0)} session flows")
    lines.append("")

    # 3. TEMUAN ANOMALI & AKTIVITAS JARINGAN
    lines.append("[-] TEMUAN ANOMALI & AKTIVITAS JARINGAN")
    lines.append(divider_minor)

    # Kueri DNS
    lines.append(f"* Kueri DNS Terdeteksi ({len(dns_queries)} entitas unik):")
    if dns_queries:
        for item in dns_queries[:25]:
            q = item.get("query", "")
            freq = item.get("frequency", 0)
            lines.append(f"  [!] {q:<45} -> {freq} request(s)")
        if len(dns_queries) > 25:
            lines.append(f"  ... (+ {len(dns_queries) - 25} kueri DNS lainnya)")
    else:
        lines.append("  (Nihil - Tidak ditemukan kueri DNS pada berkas ini)")
    lines.append("")

    # Permintaan HTTP
    lines.append(f"* Permintaan HTTP Host & URI Terdeteksi ({len(http_requests)} entitas unik):")
    if http_requests:
        for item in http_requests[:25]:
            method = item.get("method", "GET")
            full_url = item.get("full_url", "")
            freq = item.get("frequency", 0)
            lines.append(f"  [!] {method:<5} {full_url:<50} ({freq} hits)")
        if len(http_requests) > 25:
            lines.append(f"  ... (+ {len(http_requests) - 25} permintaan HTTP lainnya)")
    else:
        lines.append("  (Nihil - Tidak ditemukan lalu lintas HTTP unencrypted)")
    lines.append("")

    # Ringkasan Sesi Koneksi Utama (Top Flows)
    lines.append(f"* Sesi Koneksi Utama (Top Active Conversations):")
    if connections:
        for conn in connections[:15]:
            proto = conn.get("protocol", "TCP")
            src = f"{conn.get('src_ip', '')}:{conn.get('src_port', '')}"
            dst = f"{conn.get('dst_ip', '')}:{conn.get('dst_port', '')}"
            pkts = conn.get("packet_count", 0)
            lines.append(f"  -> [{proto:<3}] {src:<24} ===> {dst:<24} ({pkts} pkts)")
        if len(connections) > 15:
            lines.append(f"  ... (+ {len(connections) - 15} percakapan koneksi lainnya)")
    else:
        lines.append("  (Nihil - Tidak ada percakapan TCP/UDP terdata)")
    lines.append("")

    lines.append(divider_major)
    lines.append("[+] STATUS: TRIAGE SELESAI | BERKAS TEMPORARY TELAH DIBERSIHKAN DARI DISK")
    lines.append(divider_major)

    return "\n".join(lines)

async def analyze_pcap_file_as_cli_report(pcap_path: Path, filename: str, file_size_bytes: int) -> str:
    """
    Menganalisis file PCAP dan langsung menghasilkan output laporan teks terstruktur bergaya CLI.
    """
    raw_data = await analyze_pcap_file(pcap_path)
    return format_pcap_cli_report(raw_data, filename, file_size_bytes)
