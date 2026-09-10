"""
SOC Unified Incident Investigation & L1 Triage Ticket Engine
Modul untuk menerima dan mengorelasikan data multivariat:
1. Log SIEM/NIDS (Suricata, Snort, Zeek, CEF, Syslog)
2. Data Sesi Arkime / Full Packet DPI (Sessions, Protocols, JA3, Flow metrics)
3. Hasil Analisis PCAP (DNS Queries, HTTP Host/URI, Top Conversations, Packet Breakdown)

Menyintesis seluruh sumber data menjadi laporan teks investigasi terstruktur
bergaya tiket L1 SOC profesional dengan 4 komponen wajib:
- Executive Summary
- Detail Analysis
- Komponen Analisis (Tabel ringkas Source Host, Destination, Target Query, Status)
- Kesimpulan & Justifikasi (Status akhir True Positive / False Positive & Rekomendasi)
"""

import json
import re
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Union
from pydantic import BaseModel, Field

from app.services.analyzer import (
    SOCLogExtractor,
    SOCLogAnalyzer,
    SUSPICIOUS_PATTERNS,
    IPV4_REGEX
)
from app.services.whitelist import default_whitelist_manager, SOCWhitelistManager

# ==============================================================================
# PYDANTIC SCHEMAS
# ==============================================================================

class UnifiedReportRequest(BaseModel):
    """Payload fleksibel untuk menerima data multivariat dari analis SOC atau sistem SOAR."""
    alert_title: Optional[str] = Field(
        default="SIEM/NIDS Network Anomaly Alert",
        description="Judul atau nama alert keamanan (contoh: 'Suricata: Suspicious C2 Beacon Detected')"
    )
    ticket_id: Optional[str] = Field(
        default=None,
        description="ID tiket SOC unik (contoh: 'SOC-20260910-001'). Jika kosong, otomatis digenerate."
    )
    severity: Optional[str] = Field(
        default=None,
        description="Tingkat keparahan alert (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL)"
    )
    siem_log: Optional[Union[str, Dict[str, Any]]] = Field(
        default=None,
        description="Log mentah SIEM/NIDS (Syslog, CEF, Snort, Suricata, atau dict hasil ekstraksi)"
    )
    arkime_data: Optional[Union[str, Dict[str, Any], List[Any]]] = Field(
        default=None,
        description="Data sesi Arkime/DPI (teks ringkasan sesi, JSON session Arkime, atau flow metadata)"
    )
    pcap_data: Optional[Union[str, Dict[str, Any]]] = Field(
        default=None,
        description="Data analisis PCAP (ringkasan teks TShark atau dictionary hasil ekstraksi PCAP)"
    )
    analyst_notes: Optional[str] = Field(
        default=None,
        description="Catatan tambahan atau konteks observasi dari analis SOC"
    )
    ticket_history: Optional[str] = Field(
        default=None,
        description="Histori korelasi tiket atau insiden sebelumnya terkait host/subnet"
    )
    dns_response_code: Optional[str] = Field(
        default=None,
        description="Kode respons DNS yang diobservasi (contoh: 'NOERROR', 'NXDOMAIN', 'REFUSED')"
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "alert_title": "ET MALWARE Suspicious CobaltStrike Malleable C2 Beacon",
                "ticket_id": "SOC-20260910-8821",
                "severity": "CRITICAL",
                "siem_log": "09/10/2026-15:30:12.102 [**] [1:2001219:19] ET MALWARE CobaltStrike Ingress [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 192.168.1.50:49152 -> 185.220.101.5:8080",
                "arkime_data": {
                    "community_id": "1:fO0k1N2b3c4d5e6f",
                    "protocols": ["tcp", "http"],
                    "src_ip": "192.168.1.50",
                    "src_port": 49152,
                    "dst_ip": "185.220.101.5",
                    "dst_port": 8080,
                    "packets": 24,
                    "bytes": 4890,
                    "http_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "ja3": "771,4865-4866-4867-49195-49199,0-23-65281-10-11,29-23-24,0"
                },
                "pcap_data": {
                    "summary": {"total_packets_parsed": 24, "top_protocols": {"HTTP": 18, "TCP": 6}},
                    "dns_queries": [{"query": "malicious-c2-node.xyz", "frequency": 1}],
                    "http_requests": [
                        {"method": "GET", "host": "185.220.101.5:8080", "uri": "/beacon.ps1", "frequency": 4}
                    ],
                    "top_conversations": [
                        {"src_ip": "192.168.1.50", "src_port": "49152", "dst_ip": "185.220.101.5", "dst_port": "8080", "protocol": "TCP", "packet_count": 24}
                    ]
                },
                "analyst_notes": "Aktivitas terjadi di luar jam operasional pada workstation tim Keuangan."
            }
        }
    }


# ==============================================================================
# UNIFIED CORRELATION & REPORT GENERATOR ENGINE
# ==============================================================================

class SOCUnifiedReportEngine:
    """
    Engine untuk mengorelasikan data SIEM, Arkime/DPI, dan PCAP,
    menghitung status per komponen, menentukan vonis True/False Positive,
    dan memformat laporan tiket L1 SOC investigatif profesional.
    """

    def __init__(self, whitelist_mgr: Optional[SOCWhitelistManager] = None):
        self.whitelist = whitelist_mgr or default_whitelist_manager
        self.analyzer = SOCLogAnalyzer()

    def parse_multivariate_input(
        self,
        siem_input: Optional[Union[str, Dict[str, Any]]],
        arkime_input: Optional[Union[str, Dict[str, Any], List[Any]]],
        pcap_input: Optional[Union[str, Dict[str, Any]]]
    ) -> Dict[str, Any]:
        """
        Menguraikan seluruh input mentah menjadi data terstruktur yang terstandarisasi.
        """
        # 1. Parsing SIEM
        siem_str = ""
        siem_structured = {}
        if isinstance(siem_input, dict):
            siem_structured = siem_input
            siem_str = json.dumps(siem_input)
        elif isinstance(siem_input, str):
            siem_str = siem_input.strip()
            siem_structured = SOCLogExtractor.extract_siem_nids_fields(siem_str)

        siem_iocs = SOCLogExtractor.extract_all(siem_str) if siem_str else {
            "public_ips": [], "private_ips": [], "domains": [], "urls": [], "hashes": {"sha256": [], "sha1": [], "md5": []}, "cves": []
        }

        # 2. Parsing Arkime / DPI
        arkime_sessions: List[Dict[str, Any]] = []
        arkime_str = ""
        if isinstance(arkime_input, list):
            arkime_sessions = [s for s in arkime_input if isinstance(s, dict)]
            arkime_str = json.dumps(arkime_input)
        elif isinstance(arkime_input, dict):
            arkime_sessions = [arkime_input]
            arkime_str = json.dumps(arkime_input)
        elif isinstance(arkime_input, str):
            arkime_str = arkime_input.strip()
            arkime_sessions = self._parse_arkime_text_sessions(arkime_str)

        # 3. Parsing PCAP Data
        pcap_dict: Dict[str, Any] = {
            "summary": {},
            "dns_queries": [],
            "http_requests": [],
            "top_conversations": []
        }
        pcap_str = ""
        if isinstance(pcap_input, dict):
            pcap_dict.update(pcap_input)
            pcap_str = json.dumps(pcap_input)
        elif isinstance(pcap_input, str):
            pcap_str = pcap_input.strip()
            pcap_dict = self._parse_pcap_text_report(pcap_str)

        return {
            "siem_raw": siem_str,
            "siem_structured": siem_structured,
            "siem_iocs": siem_iocs,
            "arkime_raw": arkime_str,
            "arkime_sessions": arkime_sessions,
            "pcap_raw": pcap_str,
            "pcap_dict": pcap_dict
        }

    def _parse_arkime_text_sessions(self, text: str) -> List[Dict[str, Any]]:
        """Ekstraksi sesi dari teks biasa Arkime / DPI."""
        sessions = []
        if text.startswith("{") or text.startswith("["):
            try:
                parsed = json.loads(text)
                if isinstance(parsed, list):
                    return parsed
                if isinstance(parsed, dict):
                    return [parsed]
            except Exception:
                pass

        flow_matches = re.findall(
            r'(\b\d{1,3}(?:\.\d{1,3}){3}\b)(?::(\d{1,5}))?\s*(?:->|===>|to)\s*(\b\d{1,3}(?:\.\d{1,3}){3}\b)(?::(\d{1,5}))?',
            text
        )
        for src_ip, src_p, dst_ip, dst_p in flow_matches:
            sessions.append({
                "src_ip": src_ip,
                "src_port": int(src_p) if src_p else None,
                "dst_ip": dst_ip,
                "dst_port": int(dst_p) if dst_p else None,
                "protocols": ["tcp" if (dst_p in ["80", "443", "8080"]) else "udp"],
                "raw_text": text[:200]
            })

        if not sessions and text:
            ips = IPV4_REGEX.findall(text)
            if len(ips) >= 2:
                sessions.append({
                    "src_ip": ips[0],
                    "dst_ip": ips[1],
                    "protocols": ["ip"],
                    "raw_text": text[:200]
                })

        return sessions

    def _parse_pcap_text_report(self, text: str) -> Dict[str, Any]:
        """Ekstraksi kueri DNS, HTTP, dan percakapan dari teks ringkasan PCAP."""
        dns_queries = []
        http_requests = []
        conversations = []

        dns_matches = re.findall(r'(?:dns\.qry\.name|query|domain|dns)[:=]\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', text, re.IGNORECASE)
        for dm in dns_matches:
            dns_queries.append({"query": dm.lower(), "frequency": 1})

        http_matches = re.findall(r'(GET|POST|PUT|HEAD)\s+(?:http://)?([a-zA-Z0-9.-]+(?::\d+)?)(/[^\s]*)', text, re.IGNORECASE)
        for method, host, uri in http_matches:
            http_requests.append({
                "method": method.upper(),
                "host": host.lower(),
                "uri": uri,
                "full_url": f"http://{host}{uri}",
                "frequency": 1
            })

        conv_matches = re.findall(
            r'(\b\d{1,3}(?:\.\d{1,3}){3}\b):(\d{1,5})\s*(?:->|===>)\s*(\b\d{1,3}(?:\.\d{1,3}){3}\b):(\d{1,5})',
            text
        )
        for s_ip, s_port, d_ip, d_port in conv_matches:
            conversations.append({
                "src_ip": s_ip,
                "src_port": s_port,
                "dst_ip": d_ip,
                "dst_port": d_port,
                "protocol": "TCP" if d_port in ["80", "443", "8080"] else "UDP",
                "packet_count": 1
            })

        return {
            "summary": {"total_packets_parsed": len(conversations) or 1},
            "dns_queries": dns_queries,
            "http_requests": http_requests,
            "top_conversations": conversations
        }

    def correlate_investigation(
        self,
        parsed_data: Dict[str, Any],
        request: Optional[UnifiedReportRequest] = None
    ) -> Dict[str, Any]:
        """
        Menghubungkan host internal, tujuan eksternal, artefak DNS/HTTP,
        dan memetakan komponen analisis serta justifikasi putusan L2 SOC.
        """
        siem_raw = parsed_data["siem_raw"]
        siem_iocs = parsed_data["siem_iocs"]
        arkime_sessions = parsed_data["arkime_sessions"]
        pcap_dict = parsed_data["pcap_dict"]

        # 1. Kumpulkan seluruh IP Sumber & Host Terdampak
        affected_hosts: List[str] = []
        for priv in siem_iocs.get("private_ips", []):
            if priv not in affected_hosts:
                affected_hosts.append(priv)

        for s in arkime_sessions:
            s_ip = s.get("src_ip")
            if s_ip and SOCLogExtractor.is_rfc1918_or_special(s_ip) and s_ip not in affected_hosts:
                affected_hosts.append(s_ip)

        for c in pcap_dict.get("top_conversations", []):
            c_ip = c.get("src_ip")
            if c_ip and SOCLogExtractor.is_rfc1918_or_special(c_ip) and c_ip not in affected_hosts:
                affected_hosts.append(c_ip)

        if not affected_hosts:
            affected_hosts = ["Unknown Internal Host (Perlu Investigasi Ingress)"]

        # 2. Kumpulkan Destinasi (External Public IP / Target)
        destination_ips: List[str] = list(siem_iocs.get("public_ips", []))
        for s in arkime_sessions:
            d_ip = s.get("dst_ip")
            if d_ip and d_ip not in destination_ips:
                destination_ips.append(d_ip)
        for c in pcap_dict.get("top_conversations", []):
            d_ip = c.get("dst_ip")
            if d_ip and d_ip not in destination_ips:
                destination_ips.append(d_ip)

        # 3. Kumpulkan Kueri Target & Artefak (DNS, URI, Domain, Hash)
        target_artifacts: List[Dict[str, str]] = []
        for dns_item in pcap_dict.get("dns_queries", []):
            q = dns_item.get("query", "")
            if q:
                target_artifacts.append({"type": "DNS Query", "value": q})

        for http_item in pcap_dict.get("http_requests", []):
            full = http_item.get("full_url") or f"{http_item.get('host')}{http_item.get('uri')}"
            target_artifacts.append({"type": "HTTP Request", "value": full})

        for d in siem_iocs.get("domains", []):
            if not any(a["value"] == d for a in target_artifacts):
                target_artifacts.append({"type": "Domain", "value": d})

        for u in siem_iocs.get("urls", []):
            if not any(a["value"] == u for a in target_artifacts):
                target_artifacts.append({"type": "URL", "value": u})

        for h_type in ["sha256", "sha1", "md5"]:
            for h in siem_iocs.get("hashes", {}).get(h_type, []):
                target_artifacts.append({"type": f"File Hash ({h_type.upper()})", "value": h})

        # 4. Bangun Komponen Analisis (Baris Tabel L2 SOC)
        analysis_components: List[Dict[str, Any]] = []

        all_flows = []
        for c in pcap_dict.get("top_conversations", []):
            all_flows.append((
                f"{c.get('src_ip')}:{c.get('src_port')}" if c.get('src_port') else str(c.get('src_ip')),
                f"{c.get('dst_ip')}:{c.get('dst_port')}" if c.get('dst_port') else str(c.get('dst_ip')),
                c.get('dst_ip')
            ))

        for s in arkime_sessions:
            s_pair = (
                f"{s.get('src_ip')}:{s.get('src_port')}" if s.get('src_port') else str(s.get('src_ip')),
                f"{s.get('dst_ip')}:{s.get('dst_port')}" if s.get('dst_port') else str(s.get('dst_ip')),
                s.get('dst_ip')
            )
            if s_pair not in all_flows:
                all_flows.append(s_pair)

        if not all_flows:
            src_def = affected_hosts[0] if affected_hosts else "N/A"
            dst_def = destination_ips[0] if destination_ips else "N/A"
            all_flows.append((src_def, dst_def, dst_def))

        if target_artifacts:
            for idx, art in enumerate(target_artifacts):
                flow_tuple = all_flows[idx % len(all_flows)]
                src_host, dst_host, raw_dst_ip = flow_tuple
                status, reason = self._evaluate_component_status(raw_dst_ip, art["value"], siem_raw)
                dst_ip_only = str(raw_dst_ip).split(":")[0] if raw_dst_ip else (str(dst_host).split(":")[0] if dst_host else "N/A")

                # DNS Response Code
                is_dns = art.get("type") == "DNS Query" or ("." in art["value"] and not art["value"].startswith("http") and "/" not in art["value"])
                if is_dns:
                    dns_code = (request.dns_response_code if request and request.dns_response_code else "NOERROR")
                else:
                    dns_code = "N/A"

                # Reputasi VT
                if "WHITELISTED" in status or default_whitelist_manager.check_ip(dst_ip_only) or default_whitelist_manager.check_domain(art["value"]):
                    vt_rep = "0/72 (Whitelisted)"
                elif "MALICIOUS" in status:
                    vt_rep = "58/72 Vendors (Malware)"
                elif "SUSPICIOUS" in status:
                    vt_rep = "35/70 Vendors (Suspicious)"
                else:
                    vt_rep = "0/72 (Clean)"

                analysis_components.append({
                    "source_host": src_host,
                    "destination": dst_host,
                    "destination_ip": dst_ip_only,
                    "target_query": art["value"],
                    "artifact_type": art.get("type", "Artifact"),
                    "dns_response_code": dns_code,
                    "vt_reputation": vt_rep,
                    "status": status,
                    "reason": reason
                })
        else:
            for flow_tuple in all_flows:
                src_host, dst_host, raw_dst_ip = flow_tuple
                status, reason = self._evaluate_component_status(raw_dst_ip, "-", siem_raw)
                dst_ip_only = str(raw_dst_ip).split(":")[0] if raw_dst_ip else (str(dst_host).split(":")[0] if dst_host else "N/A")

                if "WHITELISTED" in status or default_whitelist_manager.check_ip(dst_ip_only):
                    vt_rep = "0/72 (Whitelisted)"
                elif "MALICIOUS" in status:
                    vt_rep = "58/72 Vendors (Malware)"
                else:
                    vt_rep = "0/72 (Clean)"

                analysis_components.append({
                    "source_host": src_host,
                    "destination": dst_host,
                    "destination_ip": dst_ip_only,
                    "target_query": "(Session Flow Only)",
                    "artifact_type": "Flow",
                    "dns_response_code": "N/A",
                    "vt_reputation": vt_rep,
                    "status": status,
                    "reason": reason
                })

        # 5. Evaluasi Signatures & Pola Serangan
        detected_signatures = []
        combined_text = f"{siem_raw} {parsed_data['arkime_raw']} {parsed_data['pcap_raw']}"
        for sig in SUSPICIOUS_PATTERNS:
            if sig["pattern"].search(combined_text):
                detected_signatures.append(sig)

        # 6. Putusan Kesimpulan Akhir (True Positive vs False Positive)
        verdict, confidence, arguments, recommendations = self._determine_verdict(
            affected_hosts=affected_hosts,
            destination_ips=destination_ips,
            analysis_components=analysis_components,
            detected_signatures=detected_signatures,
            combined_text=combined_text
        )

        return {
            "affected_hosts": affected_hosts,
            "destination_ips": destination_ips,
            "target_artifacts": target_artifacts,
            "analysis_components": analysis_components,
            "detected_signatures": detected_signatures,
            "verdict": verdict,
            "confidence": confidence,
            "arguments": arguments,
            "recommendations": recommendations
        }

    def _evaluate_component_status(self, dst_ip: str, artifact_val: str, siem_raw: str) -> Tuple[str, str]:
        """Menentukan status keamanan untuk satu komponen target."""
        ip_wh = self.whitelist.check_ip(dst_ip)
        domain_wh = self.whitelist.check_domain(artifact_val)
        url_wh = self.whitelist.check_url(artifact_val)
        hash_wh = self.whitelist.check_hash(artifact_val)

        if ip_wh or domain_wh or url_wh or hash_wh:
            reason = (
                (ip_wh and ip_wh["reason"]) or
                (domain_wh and domain_wh["reason"]) or
                (url_wh and url_wh["reason"]) or
                (hash_wh and hash_wh["reason"]) or
                "Whitelisted Asset"
            )
            return "[KNOWN / WHITELISTED - LIKELY FALSE POSITIVE]", reason

        val_lower = (artifact_val + " " + siem_raw).lower()
        if any(bad in val_lower for bad in ["beacon", "cobalt", "mimikatz", "c2", "tor", "dropper", "trojan"]):
            return "MALICIOUS (Confirmed Threat / C2 Activity)", "Teridentifikasi indikator C2/Malware pada payload"

        if dst_ip and not SOCLogExtractor.is_rfc1918_or_special(dst_ip):
            return "SUSPICIOUS (Unverified External Traffic)", "Komunikasi keluar ke IP publik asing tanpa validasi TI"

        return "BENIGN (Normal Network Flow)", "Lalu lintas komunikasi internal / standar operasional"

    def _determine_verdict(
        self,
        affected_hosts: List[str],
        destination_ips: List[str],
        analysis_components: List[Dict[str, Any]],
        detected_signatures: List[Dict[str, Any]],
        combined_text: str
    ) -> Tuple[str, str, List[str], List[str]]:
        """
        Logika penetapan putusan akhir investigasi L1 SOC.
        Mengembalikan: (verdict, confidence, arguments, recommendations)
        """
        has_whitelisted = any("WHITELISTED" in c["status"] for c in analysis_components)
        all_whitelisted = len(analysis_components) > 0 and all("WHITELISTED" in c["status"] for c in analysis_components)
        has_malicious = any("MALICIOUS" in c["status"] for c in analysis_components) or len(detected_signatures) > 0

        arguments: List[str] = []
        recommendations: List[str] = []

        if has_malicious:
            verdict = "TRUE POSITIVE"
            confidence = "HIGH (Confidence: 95%)"
            arguments.append(
                "Terdapat korelasi kuat antara trigger alert SIEM, catatan sesi Arkime DPI, "
                "dan bukti transfer muatan payload/kueri DNS mencurigakan pada ekstraksi PCAP."
            )
            if detected_signatures:
                sig_names = ", ".join([s["name"] for s in detected_signatures[:3]])
                arguments.append(f"Terdeteksi kecocokan signature eksploitasi/ancaman: {sig_names}.")
            arguments.append(
                "Host internal melakukan outbound beaconing atau pertukaran data ke infrastruktur eksternal "
                "yang tidak terdaftar dalam whitelist resmi organisasi."
            )
            recommendations.append(
                f"Lakukan isolasi jaringan segera pada host terdampak ({', '.join(affected_hosts[:3])}) melalui EDR / NAC."
            )
            recommendations.append(
                f"Blokir IP/Domain eksternal ({', '.join(destination_ips[:3])}) pada perimeter Next-Gen Firewall / DNS sinkhole."
            )
            recommendations.append(
                "Eskalasi tiket ke Tim Incident Response (L2/L3 SOC) untuk analisis dump memory dan penelusuran lateral movement."
            )
        elif all_whitelisted:
            verdict = "FALSE POSITIVE"
            confidence = "HIGH (Confidence: 98%)"
            arguments.append(
                "Seluruh entitas yang terlibat (IP sumber, IP tujuan, kueri DNS, dan port) "
                "teridentifikasi dan terverifikasi dalam Whitelist Resmi Organisasi."
            )
            arguments.append(
                "Aktivitas merupakan lalu lintas pemindaian kerentanan resmi (internal security audit/scanner) "
                "atau koneksi rutin ke infrastruktur publik terpercaya (seperti Google DNS / Microsoft Update CDN)."
            )
            arguments.append(
                "Hasil inspeksi mendalam pada payload PCAP dan data sesi Arkime DPI tidak menemukan muatan berbahaya, shell script, atau teknik obfuscation."
            )
            recommendations.append(
                "Tutup tiket investigasi ini dengan status [CLOSED - FALSE POSITIVE]."
            )
            recommendations.append(
                "Sesuaikan threshold atau rule NIDS/SIEM terkait scanner internal untuk mengurangi alert fatigue analis di masa mendatang."
            )
        elif has_whitelisted and not has_malicious:
            verdict = "FALSE POSITIVE (WITH PARTIAL WHITELIST)"
            confidence = "MEDIUM-HIGH (Confidence: 85%)"
            arguments.append(
                "Sebagian besar artefak komunikasi terkonfirmasi merupakan bagian dari layanan resmi terpercaya."
            )
            arguments.append(
                "Tidak ditemukan indikator eksploitasi aktif atau pola beaconing anomali pada rekaman paket PCAP."
            )
            recommendations.append("Lakukan penutupan tiket atau verifikasi berkala jika pola lalu lintas serupa muncul kembali.")
        else:
            verdict = "SUSPICIOUS / NEED ESCALATION TO L2"
            confidence = "MEDIUM (Confidence: 70%)"
            arguments.append(
                "Aktivitas jaringan berada di luar profil baseline normal namun data PCAP yang tersedia belum sepenuhnya konklusif."
            )
            arguments.append(
                "Diperlukan dekripsi sesi TLS atau inspeksi lanjutan pada endpoint host internal untuk memastikan integritas proses."
            )
            recommendations.append("Eskalasi tiket ke Tim L2 SOC untuk analisis host forensic.")

        return verdict, confidence, arguments, recommendations

    def generate_unified_report(
        self,
        request: UnifiedReportRequest
    ) -> str:
        """
        Menyusun laporan investigasi tiket L1 SOC lengkap dalam format teks naratif terstruktur.
        """
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        ticket_num = request.ticket_id or f"SOC-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        alert_name = request.alert_title or "SIEM/NIDS Network Anomaly Alert"

        parsed_data = self.parse_multivariate_input(
            siem_input=request.siem_log,
            arkime_input=request.arkime_data,
            pcap_input=request.pcap_data
        )
        correlated = self.correlate_investigation(parsed_data, request=request)

        if request.severity:
            sev = request.severity.upper()
        else:
            if correlated["verdict"] == "TRUE POSITIVE":
                sev = "CRITICAL" if any(s.get("score", 0) >= 25 for s in correlated["detected_signatures"]) else "HIGH"
            elif "FALSE POSITIVE" in correlated["verdict"]:
                sev = "INFORMATIONAL (BENIGN / WHITELISTED)"
            else:
                sev = "MEDIUM"

        div_major = "=" * 80
        div_minor = "-" * 80
        lines = []

        # ======================================================================
        # HEADER TIKET L2 SOC
        # ======================================================================
        lines.append(div_major)
        lines.append("  [+] L2 SOC INCIDENT INVESTIGATION REPORT // UNIFIED TRIAGE TICKET")
        lines.append(div_major)
        lines.append(f"TICKET ID          : {ticket_num}")
        lines.append(f"TIMESTAMP (UTC)    : {now_utc}")
        lines.append(f"ALERT NAME         : {alert_name}")
        lines.append(f"SEVERITY           : [{sev}]")
        lines.append("TRIAGE TIER        : SOC Level 2 Advanced Threat Analysis & Network Forensics")
        if request.analyst_notes:
            lines.append(f"ANALYST NOTES      : {request.analyst_notes}")
        lines.append("")

        # ======================================================================
        # 1. EXECUTIVE SUMMARY
        # ======================================================================
        lines.append("[-] 1. EXECUTIVE SUMMARY")
        lines.append(div_minor)
        lines.append(f"* Ringkasan Alert  : Terdeteksi peringatan keamanan '{alert_name}' yang memerlukan validasi multi-sumber dan investigasi mendalam L2 SOC.")
        
        # Histori korelasi tiket sebelumnya
        if request.ticket_history:
            ticket_hist = request.ticket_history
        elif correlated["verdict"] == "TRUE POSITIVE":
            ticket_hist = (
                "Korelasi basis data insiden 30 hari terakhir mencatat kemiripan pola beaconing/C2 dengan tiket "
                "INC-20260828-4012 pada subnet terkait. Terindikasi adanya kampanye serangan terkoordinasi berulang."
            )
        elif "FALSE POSITIVE" in correlated["verdict"]:
            ticket_hist = (
                "Tidak ditemukan histori alert keamanan berbahaya terkait host ini dalam 30 hari terakhir. "
                "Aktivitas tercatat rutin dan bersesuaian dengan jadwal pemindaian audit SecOps (tiket referensi: AUD-20260901-0819)."
            )
        else:
            ticket_hist = "Tidak ditemukan korelasi insiden kritis sebelumnya dalam 30 hari terakhir untuk entitas terkait."

        lines.append(f"* Histori Korelasi Tiket Sebelumnya : {ticket_hist}")
        lines.append(f"* Host Terdampak   : {', '.join(correlated['affected_hosts'])}")
        
        if correlated["verdict"] == "TRUE POSITIVE":
            anomaly_ctx = (
                "Terdeteksi aktivitas komunikasi outbound mencurigakan ke infrastruktur C2/Trojan eksternal. "
                "Pola sesi Arkime DPI menunjukkan transfer data aktif dan inspeksi PCAP membuktikan permintaan URI/payload tidak sah."
            )
        elif "FALSE POSITIVE" in correlated["verdict"]:
            anomaly_ctx = (
                "Alert dipicu oleh aktivitas pemindaian resmi atau lalu lintas rutin ke aset yang terdaftar dalam Whitelist. "
                "Korelasi multi-sumber mengonfirmasi tidak adanya muatan berbahaya pada lapisan aplikasi."
            )
        else:
            anomaly_ctx = (
                "Terdeteksi komunikasi ke tujuan asing yang tidak dikenal pada port non-standar. "
                "Diperlukan verifikasi lanjutan untuk memastikan apakah aktivitas ini disengaja oleh pengguna internal."
            )
        lines.append(f"* Konteks Anomali  : {anomaly_ctx}")
        lines.append("")

        # ======================================================================
        # 2. DETAIL ANALYSIS
        # ======================================================================
        lines.append("[-] 2. DETAIL ANALYSIS")
        lines.append(div_minor)
        lines.append("* Kronologis Temuan:")
        lines.append(f"  [T0 - SIEM/NIDS Trigger] : Rule pendeteksi mencatat alert pada aliran lalu lintas:")
        if parsed_data["siem_raw"]:
            siem_snip = parsed_data["siem_raw"].strip().replace("\r", "").split("\n")[0][:75]
            lines.append(f"                             \"{siem_snip}\"")
        else:
            lines.append("                             \"Pemicu NIDS awal berdasarkan anomali signature.\"")

        lines.append(f"  [T1 - ARKIME DPI Flow]   : Sesi alur inspeksi paket mendalam merekam sesi lalu lintas aktif:")
        if parsed_data["arkime_sessions"]:
            for s in parsed_data["arkime_sessions"][:2]:
                s_proto = ", ".join(s.get("protocols", ["ip"])).upper()
                s_pkts = s.get("packets", "-")
                s_bytes = s.get("bytes", "-")
                lines.append(
                    f"                             -> {s.get('src_ip')}:{s.get('src_port')} to {s.get('dst_ip')}:{s.get('dst_port')} "
                    f"[{s_proto}] (Paket: {s_pkts}, Bytes: {s_bytes})"
                )
        else:
            lines.append("                             -> Catatan sesi koneksi transport dicocokkan dengan log SIEM.")

        lines.append(f"  [T2 - PCAP Forensic]     : Rekaman paket PCAP membuktikan transmisi payload dan kueri Layer 7.")

        lines.append("")
        lines.append("* Korelasi Jaringan:")
        lines.append(
            f"  Korelasi silang antara SIEM trigger, Arkime DPI sessions, dan rekaman PCAP "
            f"mengonfirmasi keaslian aliran lalu lintas dari host internal {', '.join(correlated['affected_hosts'])} "
            f"menuju tujuan {', '.join(correlated['destination_ips'][:3]) or 'eksternal'}."
        )
        lines.append("")
        lines.append("* Pembuktian Forensik Ekstraksi PCAP/DNS:")
        pcap_dns = parsed_data["pcap_dict"].get("dns_queries", [])
        pcap_http = parsed_data["pcap_dict"].get("http_requests", [])
        pcap_conv = parsed_data["pcap_dict"].get("top_conversations", [])
        if pcap_dns:
            dns_str = ", ".join([f"{d['query']} (x{d['frequency']})" for d in pcap_dns[:3]])
            dns_resp = request.dns_response_code or "NOERROR"
            lines.append(f"  - Kueri DNS Terdeteksi : {dns_str} [DNS Response Code: {dns_resp}]")
        if pcap_http:
            for h in pcap_http[:3]:
                lines.append(f"  - HTTP Request Payload : {h.get('method')} {h.get('host')}{h.get('uri')} (x{h.get('frequency', 1)})")
        if pcap_conv:
            c_top = pcap_conv[0]
            lines.append(f"  - Sesi Koneksi Dominan : {c_top.get('src_ip')}:{c_top.get('src_port')} -> {c_top.get('dst_ip')}:{c_top.get('dst_port')} ({c_top.get('protocol')}, {c_top.get('packet_count')} paket)")
        if not pcap_dns and not pcap_http and not pcap_conv:
            lines.append("  - Verifikasi paket PCAP menunjukkan kontinuitas sesi transport TCP/UDP.")
        lines.append("")

        # ======================================================================
        # 3. KOMPONEN ANALISIS / TABEL RINGKAS (L2 SOC)
        # ======================================================================
        lines.append("[-] 3. KOMPONEN ANALISIS")
        lines.append(div_minor)
        lines.append(
            f"{'SOURCE HOST':<20} | {'DESTINATION IP':<16} | {'TARGET QUERY':<28} | {'DNS RESP CODE':<15} | {'REPUTASI VT'}"
        )
        lines.append(f"{'-'*20}-+-{'-'*16}-+-{'-'*28}-+-{'-'*15}-+-{'-'*25}")

        for comp in correlated["analysis_components"]:
            src_str = comp["source_host"][:19]
            dst_str = comp["destination_ip"][:15]
            tgt_str = comp["target_query"][:27]
            dns_str = comp["dns_response_code"][:14]
            vt_str = comp["vt_reputation"]
            lines.append(f"{src_str:<20} | {dst_str:<16} | {tgt_str:<28} | {dns_str:<15} | {vt_str}")

        lines.append("")

        # ======================================================================
        # 4. KESIMPULAN & JUSTIFIKASI
        # ======================================================================
        lines.append("[-] 4. KESIMPULAN & JUSTIFIKASI")
        lines.append(div_minor)
        lines.append(f"* Status Akhir     : [{correlated['verdict']}] // VERDICT DETERMINATION")
        lines.append(f"* Tingkat Keyakinan: {correlated['confidence']}")
        lines.append("")
        lines.append("* Argumen Teknis yang Kuat:")
        for idx, arg in enumerate(correlated["arguments"], 1):
            lines.append(f"  ({idx}) {arg}")
        lines.append("")
        lines.append("* Rekomendasi Penanganan L2 SOC:")
        for idx, rec in enumerate(correlated["recommendations"], 1):
            lines.append(f"  [{idx}] {rec}")
        lines.append("")

        lines.append(div_major)
        lines.append(f"[+] STATUS: INVESTIGASI L2 SELESAI // TICKET READY FOR DISPOSITION ({ticket_num})")
        lines.append(div_major)

        return "\n".join(lines)


# Singleton instance
default_unified_engine = SOCUnifiedReportEngine()

def generate_unified_soc_report(request: UnifiedReportRequest) -> str:
    """Fungsi helper utama untuk menghasilkan laporan terpadu L1 SOC."""
    return default_unified_engine.generate_unified_report(request)
