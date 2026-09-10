"""
SOC Log Parser Service with Integrated Whitelist Engine
Menyediakan antarmuka terpadu untuk parsing log SIEM/NIDS,
ekstraksi IoC, evaluasi whitelist, mitigasi false positive,
dan pemformatan laporan triage.
"""

from typing import Dict, Any, Optional
from app.services.analyzer import (
    SOCLogExtractor,
    SOCLogAnalyzer,
    parse_and_enrich_log_async,
    format_log_cli_report,
    extract_iocs,
    analyze_threat
)
from app.services.whitelist import (
    SOCWhitelistManager,
    default_whitelist_manager,
    DEFAULT_WHITELIST_IPS,
    DEFAULT_WHITELIST_DOMAINS,
    DEFAULT_WHITELIST_SUBNETS,
    DEFAULT_WHITELIST_HASHES
)

class SOCLogParser:
    """
    Layanan terpadu parsing log dengan evaluasi whitelist otomatis.
    """

    def __init__(self, whitelist_mgr: Optional[SOCWhitelistManager] = None):
        self.whitelist = whitelist_mgr or default_whitelist_manager
        self.extractor = SOCLogExtractor

    async def parse_and_evaluate(self, raw_log: str) -> Dict[str, Any]:
        """
        Menjalankan pipeline lengkap:
        1. Ekstraksi SIEM/NIDS & IoC
        2. Pengayaan Threat Intelijen asinkron
        3. Pencocokan Whitelist & Reduksi False Positive
        4. Pemformatan Laporan CLI
        """
        result = await parse_and_enrich_log_async(raw_log)
        return result

    def format_cli_report(self, data: Dict[str, Any], raw_log: str = "") -> str:
        """Menghasilkan laporan teks naratif CLI/Terminal."""
        return format_log_cli_report(data, raw_log=raw_log)

# Singleton parser instance
default_log_parser = SOCLogParser()
