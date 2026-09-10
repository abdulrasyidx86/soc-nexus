"""
SOC Whitelist & False Positive Filtering Engine
Modul pengelolaan daftar pengecualian (whitelist) untuk:
1. Alamat IP Publik Terpercaya (DNS Resolver ternama seperti Google 8.8.8.8, Cloudflare 1.1.1.1, Quad9 9.9.9.9).
2. Alamat IP Privat Sah / Scanner Internal (Vulnerability Scanner perusahaan seperti Nessus/Qualys, Gateway, Central Syslog).
3. Domain Sah / Terpercaya (Microsoft Windows Update, Cloudflare, Google, GitHub, Namespace Internal Perusahaan).
4. Subnet / CIDR Sah (Subnet Security Operations & Audit Tooling).
5. Hash Berkas Sah / Dikenal Bersih.

Menandai entitas dengan label khusus [KNOWN / WHITELISTED - LIKELY FALSE POSITIVE]
dan menurunkan skor ancaman secara otomatis saat terjadi kecocokan.
"""

import ipaddress
from typing import Dict, List, Any, Optional, Tuple, Set
from urllib.parse import urlparse

# ==============================================================================
# DEFAULT WHITELIST DEFINITIONS
# ==============================================================================

DEFAULT_WHITELIST_IPS: Dict[str, str] = {
    # Public Trusted Anycast DNS
    "8.8.8.8": "Trusted Public DNS Resolver (Google Primary)",
    "8.8.4.4": "Trusted Public DNS Resolver (Google Secondary)",
    "1.1.1.1": "Trusted Public DNS Resolver (Cloudflare Primary)",
    "1.0.0.1": "Trusted Public DNS Resolver (Cloudflare Secondary)",
    "9.9.9.9": "Trusted Public DNS Resolver (Quad9 Secure Anycast)",
    "149.112.112.112": "Trusted Public DNS Resolver (Quad9 Secondary)",
    "208.67.222.222": "Trusted Public DNS Resolver (Cisco OpenDNS)",
    "208.67.220.220": "Trusted Public DNS Resolver (Cisco OpenDNS)",

    # Authorized Internal Corporate Assets & Scanners
    "10.0.0.50": "Authorized Corporate Vulnerability Scanner (Nessus/Qualys Appliance)",
    "192.168.1.200": "Authorized Internal Security Audit & Penetration Testing Host",
    "172.16.0.254": "Authorized Corporate Management Edge Appliance",
    "10.10.10.10": "Internal Central Syslog, SIEM Collector & Monitoring Node"
}

DEFAULT_WHITELIST_SUBNETS: Dict[str, str] = {
    "10.0.50.0/24": "Authorized Corporate Security Operations (SecOps) Scanner Subnet",
    "192.168.254.0/24": "Authorized IT Management & Infrastructure Subnet"
}

DEFAULT_WHITELIST_DOMAINS: Dict[str, str] = {
    "google.com": "Trusted Google Core Infrastructure",
    "dns.google": "Trusted Google DNS Service",
    "cloudflare.com": "Trusted Cloudflare Core Infrastructure",
    "one.one.one.one": "Trusted Cloudflare Anycast DNS",
    "microsoft.com": "Trusted Microsoft Corporate Infrastructure",
    "windowsupdate.com": "Trusted Microsoft Windows Update Ecosystem",
    "update.microsoft.com": "Trusted Windows Update CDN",
    "azure.com": "Trusted Microsoft Azure Cloud",
    "github.com": "Trusted GitHub Source Code Platform",
    "internal.corp": "Approved Corporate Internal Domain Namespace",
    "corp.local": "Approved Corporate Active Directory Namespace",
    "company-scanner.internal": "Authorized Internal Vulnerability Scanner Host"
}

DEFAULT_WHITELIST_HASHES: Dict[str, str] = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Known Null/Empty File SHA-256 Benchmark",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709": "Known Null/Empty File SHA-1 Benchmark",
    "d41d8cd98f00b204e9800998ecf8427e": "Known Null/Empty File MD5 Benchmark"
}


# ==============================================================================
# WHITELIST MANAGER CLASS
# ==============================================================================

class SOCWhitelistManager:
    """
    Mesin pencocokan whitelist untuk mengidentifikasi entitas sah
    dan mereduksi potensi False Positive pada triage log SOC.
    """

    LABEL_WHITELISTED = "[KNOWN / WHITELISTED - LIKELY FALSE POSITIVE]"

    def __init__(self):
        self.ips: Dict[str, str] = dict(DEFAULT_WHITELIST_IPS)
        self.subnets: Dict[str, str] = dict(DEFAULT_WHITELIST_SUBNETS)
        self.domains: Dict[str, str] = dict(DEFAULT_WHITELIST_DOMAINS)
        self.hashes: Dict[str, str] = dict(DEFAULT_WHITELIST_HASHES)
        self._parsed_subnets: List[Tuple[ipaddress.IPv4Network, str]] = []
        self._init_parsed_subnets()

    def _init_parsed_subnets(self):
        self._parsed_subnets.clear()
        for cidr, reason in self.subnets.items():
            try:
                net = ipaddress.IPv4Network(cidr, strict=False)
                self._parsed_subnets.append((net, reason))
            except ValueError:
                pass

    def add_ip(self, ip: str, reason: str = "Custom Whitelisted IP") -> None:
        self.ips[ip.strip()] = reason.strip()

    def add_domain(self, domain: str, reason: str = "Custom Whitelisted Domain") -> None:
        self.domains[domain.strip().lower()] = reason.strip()

    def add_subnet(self, cidr: str, reason: str = "Custom Whitelisted Subnet") -> None:
        self.subnets[cidr.strip()] = reason.strip()
        self._init_parsed_subnets()

    def add_hash(self, file_hash: str, reason: str = "Custom Whitelisted Hash") -> None:
        self.hashes[file_hash.strip().lower()] = reason.strip()

    def check_ip(self, ip_str: str) -> Optional[Dict[str, str]]:
        """
        Mencocokkan IP dengan daftar IP atau subnet whitelist.
        """
        ip_clean = ip_str.strip()
        if ip_clean in self.ips:
            return {
                "matched": True,
                "type": "IP Address",
                "value": ip_clean,
                "status": self.LABEL_WHITELISTED,
                "reason": self.ips[ip_clean]
            }

        try:
            ip_obj = ipaddress.IPv4Address(ip_clean)
            for net, reason in self._parsed_subnets:
                if ip_obj in net:
                    return {
                        "matched": True,
                        "type": "IP Subnet CIDR",
                        "value": ip_clean,
                        "status": self.LABEL_WHITELISTED,
                        "reason": f"Masuk dalam subnet aman {net} ({reason})"
                    }
        except ValueError:
            pass

        return None

    def check_domain(self, domain_str: str) -> Optional[Dict[str, str]]:
        """
        Mencocokkan domain dengan whitelist (termasuk suffix / subdomain match).
        """
        clean_d = domain_str.strip().lower().rstrip(".")
        if clean_d in self.domains:
            return {
                "matched": True,
                "type": "Domain",
                "value": clean_d,
                "status": self.LABEL_WHITELISTED,
                "reason": self.domains[clean_d]
            }

        # Subdomain matching (e.g. sub.windowsupdate.com matches windowsupdate.com)
        for wh_domain, reason in self.domains.items():
            if clean_d.endswith("." + wh_domain):
                return {
                    "matched": True,
                    "type": "Subdomain",
                    "value": clean_d,
                    "status": self.LABEL_WHITELISTED,
                    "reason": f"Subdomain sah dari {wh_domain} ({reason})"
                }

        return None

    def check_url(self, url_str: str) -> Optional[Dict[str, str]]:
        """
        Mencocokkan host/domain pada URL dengan whitelist.
        """
        try:
            parsed = urlparse(url_str.strip())
            host = parsed.hostname
            if host:
                res_ip = self.check_ip(host)
                if res_ip:
                    return res_ip
                res_domain = self.check_domain(host)
                if res_domain:
                    return res_domain
        except Exception:
            pass
        return None

    def check_hash(self, hash_str: str) -> Optional[Dict[str, str]]:
        """
        Mencocokkan hash dengan daftar hash bersih.
        """
        clean_h = hash_str.strip().lower()
        if clean_h in self.hashes:
            return {
                "matched": True,
                "type": "File Hash",
                "value": clean_h,
                "status": self.LABEL_WHITELISTED,
                "reason": self.hashes[clean_h]
            }
        return None

    def evaluate_entities(
        self,
        entities: Dict[str, Any],
        siem_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Memeriksa seluruh entitas (Public IP, Private IP, Domain, URL, Hash, SIEM flows)
        terhadap whitelist dan menandai status kecocokan secara otomatis.
        """
        whitelisted_items: List[Dict[str, Any]] = []

        # 1. Evaluasi Public IPs
        public_ips = entities.get("public_ips", [])
        for item in public_ips:
            ip_val = item.get("ip") if isinstance(item, dict) else str(item)
            match = self.check_ip(ip_val)
            if match:
                if isinstance(item, dict):
                    item["is_whitelisted"] = True
                    item["whitelist_status"] = match["status"]
                    item["whitelist_reason"] = match["reason"]
                    # Whitelisted public IPs are benign false positives
                    item["status"] = match["status"]
                    item["reputation_score"] = 0
                whitelisted_items.append({"category": "Public IP", **match})

        # 2. Evaluasi Private IPs
        private_ips = entities.get("private_ips", [])
        for item in private_ips:
            ip_val = item.get("ip") if isinstance(item, dict) else str(ip_item := item)
            match = self.check_ip(ip_val)
            if match:
                if isinstance(item, dict):
                    item["is_whitelisted"] = True
                    item["whitelist_status"] = match["status"]
                    item["whitelist_reason"] = match["reason"]
                    item["status"] = match["status"]
                whitelisted_items.append({"category": "Private IP", **match})

        # 3. Evaluasi Domains
        domains = entities.get("domains", [])
        enriched_domains: List[Dict[str, Any]] = []
        for dom in domains:
            dom_str = dom.get("domain") if isinstance(dom, dict) else str(dom)
            match = self.check_domain(dom_str)
            if match:
                whitelisted_items.append({"category": "Domain", **match})
                enriched_domains.append({
                    "domain": dom_str,
                    "is_whitelisted": True,
                    "status": match["status"],
                    "reason": match["reason"]
                })
            else:
                enriched_domains.append({
                    "domain": dom_str,
                    "is_whitelisted": False,
                    "status": "External / Unverified",
                    "reason": "Entitas domain eksternal"
                })

        # 4. Evaluasi URLs
        urls = entities.get("urls", [])
        enriched_urls: List[Dict[str, Any]] = []
        for u in urls:
            u_str = u.get("url") if isinstance(u, dict) else str(u)
            match = self.check_url(u_str)
            if match:
                whitelisted_items.append({"category": "URL", **match})
                enriched_urls.append({
                    "url": u_str,
                    "is_whitelisted": True,
                    "status": match["status"],
                    "reason": match["reason"]
                })
            else:
                enriched_urls.append({
                    "url": u_str,
                    "is_whitelisted": False,
                    "status": "Suspicious URL",
                    "reason": "Unverified payload destination"
                })

        # 5. Evaluasi Hashes
        hashes = entities.get("hashes", [])
        for h_item in hashes:
            h_val = h_item.get("hash") if isinstance(h_item, dict) else str(h_item)
            match = self.check_hash(h_val)
            if match:
                if isinstance(h_item, dict):
                    h_item["is_whitelisted"] = True
                    h_item["whitelist_status"] = match["status"]
                    h_item["whitelist_reason"] = match["reason"]
                    h_item["status"] = match["status"]
                    h_item["reputation_score"] = 0
                whitelisted_items.append({"category": "File Hash", **match})

        # 6. Evaluasi SIEM / NIDS Flows (jika ada)
        whitelisted_flows_count = 0
        if siem_data:
            detected_flows = siem_data.get("detected_flows", [])
            for flow in detected_flows:
                src_match = self.check_ip(flow.get("src_ip", ""))
                dst_match = self.check_ip(flow.get("dst_ip", ""))
                if src_match or dst_match:
                    flow["is_whitelisted"] = True
                    flow["whitelist_status"] = self.LABEL_WHITELISTED
                    reasons = []
                    if src_match:
                        reasons.append(f"Src: {src_match['reason']}")
                    if dst_match:
                        reasons.append(f"Dst: {dst_match['reason']}")
                    flow["whitelist_reason"] = " | ".join(reasons)
                    whitelisted_flows_count += 1

        return {
            "whitelisted_items": whitelisted_items,
            "total_whitelisted": len(whitelisted_items),
            "has_whitelist_match": len(whitelisted_items) > 0,
            "whitelisted_flows_count": whitelisted_flows_count,
            "enriched_domains": enriched_domains,
            "enriched_urls": enriched_urls
        }

    def adjust_threat_score(
        self,
        base_score: int,
        whitelist_eval: Dict[str, Any],
        total_suspicious_entities: int
    ) -> Tuple[int, int, str]:
        """
        Menghitung pengurangan skor ancaman secara otomatis saat terdeteksi entitas whitelist.
        Mengembalikan: (score_akhir, poin_pengurangan, alasan)
        """
        whitelisted_count = whitelist_eval.get("total_whitelisted", 0)
        if whitelisted_count == 0:
            return base_score, 0, "Tidak ada entitas yang cocok dengan daftar whitelist."

        # Jika SELURUH entitas adalah whitelist sah (Likely 100% False Positive)
        if total_suspicious_entities > 0 and whitelisted_count >= total_suspicious_entities:
            discount = base_score
            final_score = 0
            reason = (
                f"Semua {whitelisted_count} entitas terdeteksi merupakan aset resmi / scanner terpercaya. "
                f"Skor diturunkan ke 0 (Likely False Positive)."
            )
            return final_score, discount, reason

        # Pengurangan proporsional: 35 poin per entitas whitelist kunci (maksimal 70 poin)
        discount = min(whitelisted_count * 35, 70)
        final_score = max(base_score - discount, 0)
        reason = (
            f"Terdeteksi {whitelisted_count} entitas pada whitelist resmi. "
            f"Skor ancaman dikurangi secara otomatis sebesar -{discount} poin."
        )

        return final_score, discount, reason


# Singleton default instance
default_whitelist_manager = SOCWhitelistManager()
