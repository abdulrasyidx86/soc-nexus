// SOC Nexus - Frontend Interactive Engine (L2 Incident Investigation & Triage Console)

document.addEventListener("DOMContentLoaded", () => {
    // DOM Elements - Inputs
    const alertTitleInput = document.getElementById("alertTitleInput");
    const ticketIdInput = document.getElementById("ticketIdInput");
    const severitySelect = document.getElementById("severitySelect");
    const dnsCodeInput = document.getElementById("dnsCodeInput");
    const analystNotesInput = document.getElementById("analystNotesInput");
    const logInput = document.getElementById("logInput");

    // DOM Elements - File Upload
    const supportingFileInput = document.getElementById("supportingFileInput");
    const dropZone = document.getElementById("dropZone");
    const dropZoneContent = document.getElementById("dropZoneContent");
    const fileSelectedInfo = document.getElementById("fileSelectedInfo");
    const fileNameDisplay = document.getElementById("fileNameDisplay");
    const fileSizeDisplay = document.getElementById("fileSizeDisplay");
    const removeFileBtn = document.getElementById("removeFileBtn");

    // DOM Elements - Action Buttons
    const runUnifiedBtn = document.getElementById("runUnifiedBtn");
    const runLogParseBtn = document.getElementById("runLogParseBtn");
    const resetAllBtn = document.getElementById("resetAllBtn");

    // DOM Elements - Sample Buttons
    const sampleTpBtn = document.getElementById("sampleTpBtn");
    const sampleFpBtn = document.getElementById("sampleFpBtn");
    const samplePsBtn = document.getElementById("samplePsBtn");
    const sampleWebBtn = document.getElementById("sampleWebBtn");

    // DOM Elements - State Displays
    const loadingState = document.getElementById("loadingState");
    const loadingStatusText = document.getElementById("loadingStatusText");
    const loadingSubText = document.getElementById("loadingSubText");
    const emptyState = document.getElementById("emptyState");
    const reportSection = document.getElementById("reportSection");

    // DOM Elements - Report Display
    const verdictBanner = document.getElementById("verdictBanner");
    const verdictIconContainer = document.getElementById("verdictIconContainer");
    const verdictStatusBadge = document.getElementById("verdictStatusBadge");
    const verdictSummaryText = document.getElementById("verdictSummaryText");
    const verdictConfidenceText = document.getElementById("verdictConfidenceText");
    const reportOutputText = document.getElementById("reportOutputText");
    const copyReportBtn = document.getElementById("copyReportBtn");
    const downloadReportBtn = document.getElementById("downloadReportBtn");

    // DOM Elements - IoC Badges
    const publicIpsBadges = document.getElementById("publicIpsBadges");
    const privateIpsBadges = document.getElementById("privateIpsBadges");
    const domainsBadges = document.getElementById("domainsBadges");
    const hashesBadges = document.getElementById("hashesBadges");

    // DOM Elements - Metrics
    const metricLogsCount = document.getElementById("metricLogsCount");
    const metricTpCount = document.getElementById("metricTpCount");
    const metricFpCount = document.getElementById("metricFpCount");
    const latencyDisplay = document.getElementById("latencyDisplay");

    // DOM Elements - Quick Lookup
    const lookupInput = document.getElementById("lookupInput");
    const lookupBtn = document.getElementById("lookupBtn");
    const lookupResult = document.getElementById("lookupResult");

    // Session State Tracking
    let currentAttachedFile = null;
    let sessionLogsCount = 0;
    let sessionTpCount = 0;
    let sessionFpCount = 0;
    let lastGeneratedTicketId = "";

    // =========================================================================
    // 1. FILE DRAG & DROP AND SELECTION HANDLERS
    // =========================================================================

    if (dropZone && supportingFileInput) {
        dropZone.addEventListener("click", (e) => {
            if (e.target !== removeFileBtn && !removeFileBtn?.contains(e.target)) {
                supportingFileInput.click();
            }
        });

        supportingFileInput.addEventListener("change", (e) => {
            if (e.target.files && e.target.files[0]) {
                handleFileSelected(e.target.files[0]);
            }
        });

        ["dragenter", "dragover"].forEach((eventName) => {
            dropZone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropZone.classList.add("border-cyan-400", "bg-cyan-950/20");
            });
        });

        ["dragleave", "drop"].forEach((eventName) => {
            dropZone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropZone.classList.remove("border-cyan-400", "bg-cyan-950/20");
            });
        });

        dropZone.addEventListener("drop", (e) => {
            const files = e.dataTransfer?.files;
            if (files && files.length > 0) {
                handleFileSelected(files[0]);
            }
        });
    }

    if (removeFileBtn) {
        removeFileBtn.addEventListener("click", (e) => {
            e.stopPropagation();
            clearAttachedFile();
            showToast("Berkas pendukung telah dihapus.", "info");
        });
    }

    function handleFileSelected(file) {
        if (file.size > 25 * 1024 * 1024) {
            showToast("Ukuran berkas melebihi batas 25 MB.", "error");
            return;
        }

        currentAttachedFile = file;
        const sizeFormatted = (file.size / (1024 * 1024)).toFixed(2) + " MB";
        
        if (fileNameDisplay) fileNameDisplay.textContent = file.name;
        if (fileSizeDisplay) fileSizeDisplay.textContent = `${sizeFormatted} • Siap dianotasi`;

        if (dropZoneContent) dropZoneContent.classList.add("hidden");
        if (fileSelectedInfo) {
            fileSelectedInfo.classList.remove("hidden");
            fileSelectedInfo.classList.add("flex");
        }

        // Jika file berformat teks (.log, .txt, .json), baca dan tawarkan untuk isi ke log input
        const ext = file.name.split(".").pop().toLowerCase();
        if (["log", "txt", "json"].includes(ext)) {
            const reader = new FileReader();
            reader.onload = (event) => {
                if (!logInput.value.trim() && event.target?.result) {
                    logInput.value = event.target.result;
                    showToast(`Isi log dari berkas [${file.name}] dimuat ke formulir.`, "info");
                }
            };
            reader.readAsText(file);
        } else {
            showToast(`Berkas PCAP [${file.name}] siap dikorelasikan forensik!`, "info");
        }
    }

    function clearAttachedFile() {
        currentAttachedFile = null;
        if (supportingFileInput) supportingFileInput.value = "";
        if (dropZoneContent) dropZoneContent.classList.remove("hidden");
        if (fileSelectedInfo) {
            fileSelectedInfo.classList.add("hidden");
            fileSelectedInfo.classList.remove("flex");
        }
    }

    // =========================================================================
    // 2. SAMPLE LOG LOADERS
    // =========================================================================

    if (sampleTpBtn) {
        sampleTpBtn.addEventListener("click", async () => {
            alertTitleInput.value = "ET MALWARE CobaltStrike Malleable C2 Beacon";
            ticketIdInput.value = ""; // Dikosongkan agar diterbitkan otomatis saat triage
            severitySelect.value = "CRITICAL";
            dnsCodeInput.value = "NOERROR";
            analystNotesInput.value = ""; // Opsional
            await loadSampleToLog("cobalt_strike_c2");
        });
    }

    if (sampleFpBtn) {
        sampleFpBtn.addEventListener("click", async () => {
            alertTitleInput.value = "NIDS Potential Outbound Scanner Port Sweep";
            ticketIdInput.value = ""; // Dikosongkan agar diterbitkan otomatis saat triage
            severitySelect.value = "INFORMATIONAL";
            dnsCodeInput.value = "NOERROR";
            analystNotesInput.value = ""; // Opsional
            await loadSampleToLog("whitelist_scanner");
        });
    }

    if (samplePsBtn) {
        samplePsBtn.addEventListener("click", async () => {
            alertTitleInput.value = "Suspicious Encoded PowerShell Execution (Event 4688)";
            ticketIdInput.value = "";
            severitySelect.value = "HIGH";
            dnsCodeInput.value = "NOERROR";
            analystNotesInput.value = "";
            await loadSampleToLog("powershell_malware");
        });
    }

    if (sampleWebBtn) {
        sampleWebBtn.addEventListener("click", async () => {
            alertTitleInput.value = "Web Application SQL Injection & Path Traversal";
            ticketIdInput.value = "";
            severitySelect.value = "HIGH";
            dnsCodeInput.value = "NOERROR";
            analystNotesInput.value = "";
            await loadSampleToLog("web_attack");
        });
    }

    async function loadSampleToLog(sampleType) {
        try {
            const res = await fetch(`/api/sample-log/${sampleType}`);
            const data = await res.json();
            if (data.status === "success") {
                logInput.value = data.content;
                showToast(`Sample [${sampleType}] berhasil dimuat!`, "info");
            }
        } catch (err) {
            console.error("Gagal mengambil sample log:", err);
            showToast("Gagal memuat sample log dari server.", "error");
        }
    }

    // =========================================================================
    // 3. INTERACTIVE RESET BUTTON (CLEAR / NEW ANALYSIS)
    // =========================================================================

    if (resetAllBtn) {
        resetAllBtn.addEventListener("click", () => {
            // Bersihkan semua input teks
            logInput.value = "";
            alertTitleInput.value = "";
            ticketIdInput.value = "";
            severitySelect.value = "";
            dnsCodeInput.value = "";
            analystNotesInput.value = "";

            // Bersihkan upload file
            clearAttachedFile();

            // Bersihkan panel laporan hasil
            if (reportOutputText) reportOutputText.textContent = "";
            if (publicIpsBadges) publicIpsBadges.innerHTML = "";
            if (privateIpsBadges) privateIpsBadges.innerHTML = "";
            if (domainsBadges) domainsBadges.innerHTML = "";
            if (hashesBadges) hashesBadges.innerHTML = "";

            // Kembalikan status visual ke kondisi awal (Empty State)
            if (reportSection) reportSection.classList.add("hidden");
            if (loadingState) loadingState.classList.add("hidden");
            if (emptyState) emptyState.classList.remove("hidden");

            // Feedback interaktif
            showToast("Seluruh formulir & panel laporan telah di-reset. Siap untuk analisis berikutnya.", "success");
        });
    }

    // =========================================================================
    // 4. ACTION: JALANKAN ANALISIS L2 SOC (UNIFIED REPORT)
    // =========================================================================

    if (runUnifiedBtn) {
        runUnifiedBtn.addEventListener("click", async () => {
            const rawLog = logInput.value.trim();
            if (!rawLog && !currentAttachedFile) {
                showToast("Silakan masukkan teks log atau unggah berkas pendukung terlebih dahulu!", "warning");
                return;
            }

            // Tampilkan Loading State
            if (emptyState) emptyState.classList.add("hidden");
            if (reportSection) reportSection.classList.add("hidden");
            if (loadingState) loadingState.classList.remove("hidden");
            if (loadingStatusText) loadingStatusText.textContent = "MENJALANKAN INVESTIGASI L2 SOC...";
            if (loadingSubText) loadingSubText.textContent = "Mengorelasikan data multivariat, kueri DNS, dan pengayaan reputasi AbuseIPDB & VirusTotal...";

            const startTime = performance.now();

            try {
                let pcapDataSummary = null;

                // Jika ada file PCAP yang diunggah, lakukan ekstraksi TShark terlebih dahulu
                if (currentAttachedFile && (currentAttachedFile.name.endsWith(".pcap") || currentAttachedFile.name.endsWith(".pcapng") || currentAttachedFile.name.endsWith(".cap"))) {
                    if (loadingSubText) loadingSubText.textContent = "Menganalisis berkas PCAP melalui utilitas CLI TShark...";
                    const formData = new FormData();
                    formData.append("file", currentAttachedFile);
                    try {
                        const pcapRes = await fetch("/api/analyze-pcap?format=json", {
                            method: "POST",
                            body: formData
                        });
                        if (pcapRes.ok) {
                            const pcapJson = await pcapRes.json();
                            pcapDataSummary = pcapJson.data || pcapJson.cli_report;
                        }
                    } catch (pcapErr) {
                        console.warn("PCAP preprocessing failed, continuing with log data:", pcapErr);
                    }
                }

                // Susun Payload Investigasi L2 SOC
                const payload = {
                    alert_title: alertTitleInput.value.trim() || "SIEM/NIDS Network Anomaly Alert",
                    ticket_id: ticketIdInput.value.trim() || null,
                    severity: severitySelect.value || null,
                    siem_log: rawLog || (currentAttachedFile ? `Attached File: ${currentAttachedFile.name}` : ""),
                    pcap_data: pcapDataSummary,
                    analyst_notes: analystNotesInput.value.trim() || null,
                    dns_response_code: dnsCodeInput.value.trim() || null
                };

                if (loadingSubText) loadingSubText.textContent = "Menghubungkan IoC dan menyintesis laporan investigasi tiket L2 SOC...";

                const response = await fetch("/api/unified-report?format=json", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(payload)
                });

                const latency = Math.round(performance.now() - startTime);
                if (latencyDisplay) latencyDisplay.textContent = `${latency} ms`;

                if (!response.ok) {
                    const errText = await response.text();
                    throw new Error(errText || "Gagal menghasilkan laporan L2 SOC");
                }

                const result = await response.json();
                lastGeneratedTicketId = result.ticket_id || payload.ticket_id || "SOC-L2-TICKET";

                // Render Laporan Tiket L2 SOC
                renderUnifiedReport(result.report, result.ticket_id);

                // Jalankan ekstraksi IoC untuk matriks interaktif di bawahnya
                enrichAndDisplayIocs(rawLog);

                // Update metrik sesi
                sessionLogsCount++;
                if (metricLogsCount) metricLogsCount.textContent = sessionLogsCount;

                showToast("Investigasi L2 SOC berhasil diselesaikan!", "success");

            } catch (err) {
                console.error("Error running unified investigation:", err);
                showToast("Terjadi kendala saat menganalisis: " + err.message, "error");
                if (emptyState) emptyState.classList.remove("hidden");
            } finally {
                if (loadingState) loadingState.classList.add("hidden");
            }
        });
    }

    // =========================================================================
    // 5. ACTION: PARSE LOG SAJA (/api/parse-log)
    // =========================================================================

    if (runLogParseBtn) {
        runLogParseBtn.addEventListener("click", async () => {
            const rawLog = logInput.value.trim();
            if (!rawLog) {
                showToast("Silakan masukkan teks log terlebih dahulu!", "warning");
                return;
            }

            if (emptyState) emptyState.classList.add("hidden");
            if (reportSection) reportSection.classList.add("hidden");
            if (loadingState) loadingState.classList.remove("hidden");
            if (loadingStatusText) loadingStatusText.textContent = "PARSING LOG SIEM & ENRICHMENT TI...";
            if (loadingSubText) loadingSubText.textContent = "Mengekstrak IoC (IP Publik, Hash, Domain) dan query AbuseIPDB / VirusTotal...";

            const startTime = performance.now();

            try {
                const response = await fetch("/api/parse-log?format=json", {
                    method: "POST",
                    headers: { "Content-Type": "text/plain" },
                    body: rawLog
                });

                const latency = Math.round(performance.now() - startTime);
                if (latencyDisplay) latencyDisplay.textContent = `${latency} ms`;

                if (!response.ok) {
                    throw new Error(await response.text());
                }

                const result = await response.json();
                renderUnifiedReport(result.cli_report || "Log Triage Completed", "LOG-TRIAGE");
                if (result.data) {
                    renderIocBadges(result.data.entities || result.data);
                }

                sessionLogsCount++;
                if (metricLogsCount) metricLogsCount.textContent = sessionLogsCount;
                showToast("Parsing log SIEM selesai!", "success");

            } catch (err) {
                console.error("Error parsing log:", err);
                showToast("Gagal parsing log: " + err.message, "error");
                if (emptyState) emptyState.classList.remove("hidden");
            } finally {
                if (loadingState) loadingState.classList.add("hidden");
            }
        });
    }

    // =========================================================================
    // 6. RENDER LOGIC: L2 SOC TICKET REPORT & VERDICT BANNER
    // =========================================================================

    function renderUnifiedReport(reportText, ticketId = "") {
        if (!reportText) return;

        if (reportOutputText) {
            reportOutputText.textContent = reportText;
        }

        // Deteksi Putusan Akhir (Verdict) dari teks laporan
        const isTruePositive = reportText.includes("[TRUE POSITIVE]");
        const isFalsePositive = reportText.includes("[FALSE POSITIVE]");

        if (verdictBanner && verdictStatusBadge && verdictIconContainer && verdictSummaryText) {
            verdictBanner.className = "p-4 rounded-xl border shadow-xl transition-all duration-300 flex items-center justify-between gap-4 ";

            if (isTruePositive) {
                sessionTpCount++;
                if (metricTpCount) metricTpCount.textContent = sessionTpCount;

                verdictBanner.classList.add("bg-rose-950/40", "border-rose-700/80", "glow-rose");
                verdictIconContainer.className = "w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 font-black text-lg bg-rose-900/80 text-rose-200 border border-rose-600";
                verdictIconContainer.textContent = "!";
                verdictStatusBadge.className = "px-2.5 py-0.5 text-xs font-mono font-bold rounded-md uppercase tracking-wider bg-rose-600 text-white shadow-sm";
                verdictStatusBadge.textContent = "TRUE POSITIVE // CONFIRMED THREAT";
                verdictSummaryText.textContent = "Terdeteksi aktivitas C2 beaconing / malware muatan berbahaya. Lakukan isolasi host segera!";
                if (verdictConfidenceText) {
                    verdictConfidenceText.textContent = "HIGH (95%)";
                    verdictConfidenceText.className = "text-sm font-mono font-black text-rose-400";
                }
            } else if (isFalsePositive) {
                sessionFpCount++;
                if (metricFpCount) metricFpCount.textContent = sessionFpCount;

                verdictBanner.classList.add("bg-emerald-950/40", "border-emerald-700/80", "glow-emerald");
                verdictIconContainer.className = "w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 font-black text-lg bg-emerald-900/80 text-emerald-200 border border-emerald-600";
                verdictIconContainer.textContent = "✓";
                verdictStatusBadge.className = "px-2.5 py-0.5 text-xs font-mono font-bold rounded-md uppercase tracking-wider bg-emerald-600 text-white shadow-sm";
                verdictStatusBadge.textContent = "FALSE POSITIVE // WHITELISTED";
                verdictSummaryText.textContent = "Lalu lintas terverifikasi sah dari scanner internal terotorisasi atau layanan publik terpercaya.";
                if (verdictConfidenceText) {
                    verdictConfidenceText.textContent = "HIGH (98%)";
                    verdictConfidenceText.className = "text-sm font-mono font-black text-emerald-400";
                }
            } else {
                verdictBanner.classList.add("bg-amber-950/40", "border-amber-700/80", "glow-amber");
                verdictIconContainer.className = "w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 font-black text-lg bg-amber-900/80 text-amber-200 border border-amber-600";
                verdictIconContainer.textContent = "?";
                verdictStatusBadge.className = "px-2.5 py-0.5 text-xs font-mono font-bold rounded-md uppercase tracking-wider bg-amber-600 text-white shadow-sm";
                verdictStatusBadge.textContent = "SUSPICIOUS // ESCALATE";
                verdictSummaryText.textContent = "Anomali lalu lintas terdeteksi; eskalasi ke Tim L2/L3 untuk investigasi memori endpoint.";
                if (verdictConfidenceText) {
                    verdictConfidenceText.textContent = "MEDIUM (70%)";
                    verdictConfidenceText.className = "text-sm font-mono font-black text-amber-400";
                }
            }
        }

        // Tampilkan panel laporan dan sembunyikan empty state
        if (emptyState) emptyState.classList.add("hidden");
        if (reportSection) reportSection.classList.remove("hidden");

        // Scroll halus ke panel laporan
        reportSection.scrollIntoView({ behavior: "smooth", block: "start" });
    }

    // =========================================================================
    // 7. ENRICHMENT & IOC BADGES RENDERER
    // =========================================================================

    async function enrichAndDisplayIocs(rawLog) {
        if (!rawLog) return;
        try {
            const res = await fetch("/api/parse-log?format=json", {
                method: "POST",
                headers: { "Content-Type": "text/plain" },
                body: rawLog
            });
            if (res.ok) {
                const data = await res.json();
                renderIocBadges(data.data?.entities || data.data);
            }
        } catch (e) {
            console.warn("IoC badge extraction background error:", e);
        }
    }

    function renderIocBadges(entities) {
        if (!entities) return;

        // 1. Public IPs
        if (publicIpsBadges) {
            publicIpsBadges.innerHTML = "";
            const pubIps = entities.public_ips || [];
            if (pubIps.length === 0) {
                publicIpsBadges.innerHTML = '<span class="text-[11px] font-mono text-slate-500">Tidak ada IP publik eksternal</span>';
            } else {
                pubIps.forEach((item) => {
                    const ip = typeof item === "string" ? item : item.ip;
                    const score = typeof item === "object" ? item.reputation_score : null;
                    const badge = createBadge(ip, "rose", score !== null ? `Abuse: ${score}%` : null);
                    publicIpsBadges.appendChild(badge);
                });
            }
        }

        // 2. Private IPs
        if (privateIpsBadges) {
            privateIpsBadges.innerHTML = "";
            const privIps = entities.private_ips || [];
            if (privIps.length === 0) {
                privateIpsBadges.innerHTML = '<span class="text-[11px] font-mono text-slate-500">Tidak ada IP privat RFC 1918</span>';
            } else {
                privIps.forEach((item) => {
                    const ip = typeof item === "string" ? item : item.ip;
                    const badge = createBadge(ip, "slate", "Protected");
                    privateIpsBadges.appendChild(badge);
                });
            }
        }

        // 3. Domains
        if (domainsBadges) {
            domainsBadges.innerHTML = "";
            const domains = entities.domains || [];
            if (domains.length === 0) {
                domainsBadges.innerHTML = '<span class="text-[11px] font-mono text-slate-500">Tidak ada domain terdeteksi</span>';
            } else {
                domains.forEach((d) => {
                    const badge = createBadge(d, "cyan");
                    domainsBadges.appendChild(badge);
                });
            }
        }

        // 4. Hashes
        if (hashesBadges) {
            hashesBadges.innerHTML = "";
            const hashesList = [];
            if (entities.hashes) {
                if (Array.isArray(entities.hashes)) {
                    entities.hashes.forEach(h => hashesList.push(h));
                } else {
                    ["sha256", "sha1", "md5"].forEach(type => {
                        (entities.hashes[type] || []).forEach(h => hashesList.push({ hash: h, hash_type: type.toUpperCase() }));
                    });
                }
            }
            if (hashesList.length === 0) {
                hashesBadges.innerHTML = '<span class="text-[11px] font-mono text-slate-500">Tidak ada file hash terdeteksi</span>';
            } else {
                hashesList.forEach((item) => {
                    const hashVal = typeof item === "string" ? item : item.hash;
                    const hType = typeof item === "object" ? item.hash_type : "";
                    const badge = createBadge(hashVal.slice(0, 16) + "...", "amber", hType || "VT Hash", hashVal);
                    hashesBadges.appendChild(badge);
                });
            }
        }
    }

    function createBadge(text, color, extraTag = null, copyValue = null) {
        const span = document.createElement("span");
        span.className = `inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono border cursor-pointer select-all transition-all hover:scale-105 active:scale-95 `;
        
        if (color === "rose") {
            span.className += "bg-rose-950/60 text-rose-300 border-rose-800/80 hover:bg-rose-900/60";
        } else if (color === "emerald") {
            span.className += "bg-emerald-950/60 text-emerald-300 border-emerald-800/80 hover:bg-emerald-900/60";
        } else if (color === "cyan") {
            span.className += "bg-cyan-950/60 text-cyan-300 border-cyan-800/80 hover:bg-cyan-900/60";
        } else if (color === "amber") {
            span.className += "bg-amber-950/60 text-amber-300 border-amber-800/80 hover:bg-amber-900/60";
        } else {
            span.className += "bg-slate-900 text-slate-300 border-slate-700 hover:bg-slate-800";
        }

        span.textContent = text;

        if (extraTag) {
            const tag = document.createElement("span");
            tag.className = "text-[9px] px-1 rounded bg-black/40 font-semibold";
            tag.textContent = extraTag;
            span.appendChild(tag);
        }

        span.addEventListener("click", () => {
            const toCopy = copyValue || text;
            navigator.clipboard.writeText(toCopy);
            showToast(`[${toCopy}] disalin ke clipboard!`, "info");
        });

        return span;
    }

    // =========================================================================
    // 8. UTILITIES: COPY REPORT & DOWNLOAD TXT
    // =========================================================================

    if (copyReportBtn) {
        copyReportBtn.addEventListener("click", () => {
            if (reportOutputText && reportOutputText.textContent) {
                navigator.clipboard.writeText(reportOutputText.textContent);
                showToast("Laporan investigasi tiket L2 SOC berhasil disalin ke clipboard!", "success");
            }
        });
    }

    if (downloadReportBtn) {
        downloadReportBtn.addEventListener("click", () => {
            if (reportOutputText && reportOutputText.textContent) {
                const text = reportOutputText.textContent;
                const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                const filename = (lastGeneratedTicketId || "SOC-L2-TICKET") + ".txt";
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                showToast(`Berkas [${filename}] berhasil diunduh!`, "success");
            }
        });
    }

    // =========================================================================
    // 9. INSTANT IOC LOOKUP TOOL
    // =========================================================================

    if (lookupBtn && lookupInput) {
        lookupBtn.addEventListener("click", async () => {
            const val = lookupInput.value.trim();
            if (!val) {
                showToast("Masukkan IP publik, domain, atau hash!", "warning");
                return;
            }

            lookupBtn.disabled = true;
            lookupBtn.textContent = "...";

            try {
                const res = await fetch("/api/lookup/ioc", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ ioc: val })
                });

                if (res.ok) {
                    const data = await res.json();
                    renderLookupResult(data.data);
                } else {
                    showToast("Lookup gagal dijalankan", "error");
                }
            } catch (e) {
                showToast("Kendala jaringan saat lookup: " + e.message, "error");
            } finally {
                lookupBtn.disabled = false;
                lookupBtn.textContent = "Cek";
            }
        });
    }

    function renderLookupResult(data) {
        if (!lookupResult || !data) return;
        lookupResult.classList.remove("hidden");
        const status = data.status || "Unknown";
        const isSafe = status.toLowerCase().includes("clean") || status.toLowerCase().includes("whitelisted");
        
        lookupResult.innerHTML = `
            <div class="p-2.5 rounded-lg border text-xs font-mono space-y-1 ${isSafe ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300' : 'bg-rose-950/40 border-rose-800 text-rose-300'}">
                <div class="flex items-center justify-between">
                    <span class="font-bold">${data.ioc || data.value || 'Target'}</span>
                    <span class="px-1.5 py-0.5 rounded text-[10px] bg-black/40 font-bold">${status}</span>
                </div>
                <div class="text-[10px] text-slate-400">Tipe: ${data.type || 'IoC'} • Reputasi: ${data.reputation_score ?? 'N/A'}</div>
            </div>
        `;
    }

    // =========================================================================
    // 10. TOAST NOTIFICATION UTILITY
    // =========================================================================

    function showToast(message, type = "info") {
        const container = document.getElementById("toastContainer");
        if (!container) return;

        const toast = document.createElement("div");
        toast.className = "px-4 py-2.5 rounded-lg shadow-2xl text-xs font-mono flex items-center gap-2 border transition-all duration-300 opacity-0 translate-y-2 pointer-events-auto ";

        if (type === "success") {
            toast.className += "bg-emerald-950 text-emerald-200 border-emerald-700 shadow-emerald-950/50";
            toast.innerHTML = `<svg class="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg> <span>${message}</span>`;
        } else if (type === "error") {
            toast.className += "bg-rose-950 text-rose-200 border-rose-700 shadow-rose-950/50";
            toast.innerHTML = `<svg class="w-4 h-4 text-rose-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg> <span>${message}</span>`;
        } else if (type === "warning") {
            toast.className += "bg-amber-950 text-amber-200 border-amber-700 shadow-amber-950/50";
            toast.innerHTML = `<svg class="w-4 h-4 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg> <span>${message}</span>`;
        } else {
            toast.className += "bg-slate-900 text-cyan-200 border-cyan-800 shadow-cyan-950/50";
            toast.innerHTML = `<svg class="w-4 h-4 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg> <span>${message}</span>`;
        }

        container.appendChild(toast);

        // Fade in
        requestAnimationFrame(() => {
            toast.classList.remove("opacity-0", "translate-y-2");
            toast.classList.add("opacity-100", "translate-y-0");
        });

        // Auto remove after 3.5s
        setTimeout(() => {
            toast.classList.remove("opacity-100", "translate-y-0");
            toast.classList.add("opacity-0", "translate-y-2");
            setTimeout(() => {
                if (toast.parentNode) {
                    toast.parentNode.removeChild(toast);
                }
            }, 300);
        }, 3500);
    }
});
