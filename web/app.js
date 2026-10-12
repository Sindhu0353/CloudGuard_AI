document.addEventListener("DOMContentLoaded", () => {
    // DOM Elements
    const dropZone = document.getElementById("dropZone");
    const fileInput = document.getElementById("fileInput");
    const browseBtn = document.getElementById("browseBtn");
    const selectedFileName = document.getElementById("selectedFileName");
    const scanBtn = document.getElementById("scanBtn");
    const alertBox = document.getElementById("alertBox");
    const resultsContainer = document.getElementById("resultsContainer");
    
    const resAnalyzedCount = document.getElementById("resAnalyzedCount");
    const detectedFormat = document.getElementById("detectedFormat");
    const totalFindingsCount = document.getElementById("totalFindingsCount");
    const overallRiskScore = document.getElementById("overallRiskScore");
    
    const cntCritical = document.getElementById("cntCritical");
    const cntHigh = document.getElementById("cntHigh");
    const cntMedium = document.getElementById("cntMedium");
    const cntLow = document.getElementById("cntLow");
    
    const findingsTableBody = document.getElementById("findingsTableBody");
    const historyTableBody = document.getElementById("historyTableBody");
    const baselineTableBody = document.getElementById("baselineTableBody");
    
    const downloadHtmlBtn = document.getElementById("downloadHtmlBtn");
    const downloadJsonBtn = document.getElementById("downloadJsonBtn");

    // Baseline Navigation & Filters
    const viewBaselineHeaderBtn = document.getElementById("viewBaselineHeaderBtn");
    const toggleBaselineBtn = document.getElementById("toggleBaselineBtn");
    const baselineSection = document.getElementById("baselineSection");
    const baselineSearchInput = document.getElementById("baselineSearchInput");
    const severityFilter = document.getElementById("severityFilter");

    // Remediation Modal
    const remediationModal = document.getElementById("remediationModal");
    const closeModalBtn = document.getElementById("closeModalBtn");
    const dismissModalBtn = document.getElementById("dismissModalBtn");
    const confirmRemediateBtn = document.getElementById("confirmRemediateBtn");
    const originalConfigPre = document.getElementById("originalConfigPre");
    const remediatedConfigPre = document.getElementById("remediatedConfigPre");
    const remediationMessage = document.getElementById("remediationMessage");
    const postScanNotice = document.getElementById("postScanNotice");

    // Rule Detail Modal
    const ruleDetailModal = document.getElementById("ruleDetailModal");
    const closeRuleModalBtn = document.getElementById("closeRuleModalBtn");
    const dismissRuleModalBtn = document.getElementById("dismissRuleModalBtn");
    const modalRuleTitle = document.getElementById("modalRuleTitle");
    const modalRuleContent = document.getElementById("modalRuleContent");

    // Application state
    let activeFileContent = "";
    let activeFileName = "";
    let currentScanId = null;
    let activeScanResult = null;
    let activeSimTarget = null;
    let allBaselineRules = [];

    // Load initial data
    loadHistory();
    loadBaselineRules();

    // Event Listeners for File Selection
    browseBtn.addEventListener("click", () => fileInput.click());
    
    fileInput.addEventListener("change", (e) => {
        if (e.target.files.length > 0) handleFileSelection(e.target.files[0]);
    });

    dropZone.addEventListener("dragover", (e) => {
        e.preventDefault();
        dropZone.classList.add("dragover");
    });

    dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragover"));

    dropZone.addEventListener("drop", (e) => {
        e.preventDefault();
        dropZone.classList.remove("dragover");
        if (e.dataTransfer.files.length > 0) handleFileSelection(e.dataTransfer.files[0]);
    });

    function handleFileSelection(file) {
        if (!file.name.endsWith(".json")) {
            showAlert("Please select a valid JSON configuration file.", "error");
            return;
        }
        activeFileName = file.name;
        selectedFileName.textContent = file.name;
        
        const reader = new FileReader();
        reader.onload = (e) => {
            activeFileContent = e.target.result;
            scanBtn.disabled = false;
            hideAlert();
        };
        reader.readAsText(file);
    }

    function showAlert(msg, type = "error") {
        alertBox.textContent = msg;
        alertBox.className = `alert alert-${type}`;
        alertBox.classList.remove("hidden");
    }

    function hideAlert() {
        alertBox.classList.add("hidden");
    }

    // Trigger Scan
    scanBtn.addEventListener("click", async () => {
        if (!activeFileContent) return;
        scanBtn.disabled = true;
        scanBtn.textContent = "Scanning Baseline...";

        try {
            const res = await fetch("/api/scan", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ filename: activeFileName, content: activeFileContent })
            });

            const data = await res.json();
            if (!data.success) {
                showAlert(data.error || "Scan failed.", "error");
                resultsContainer.classList.add("hidden");
            } else {
                activeScanResult = data;
                currentScanId = data.scan_id;
                renderScanResults(data);
                loadHistory();
            }
        } catch (err) {
            showAlert("Network connection error.", "error");
        } finally {
            scanBtn.disabled = false;
            scanBtn.textContent = "Start Security Scan";
        }
    });

    function renderScanResults(data) {
        resAnalyzedCount.textContent = data.resources_analyzed;
        detectedFormat.textContent = `Format: ${data.format}`;
        totalFindingsCount.textContent = data.total_findings;
        overallRiskScore.textContent = `${data.overall_risk_score} / 100`;

        const counts = data.summary_counts || {};
        cntCritical.textContent = `Critical: ${counts.critical || 0}`;
        cntHigh.textContent = `High: ${counts.high || 0}`;
        cntMedium.textContent = `Medium: ${counts.medium || 0}`;
        cntLow.textContent = `Low: ${counts.low || 0}`;

        findingsTableBody.innerHTML = "";
        
        if (data.findings.length === 0) {
            findingsTableBody.innerHTML = `
                <tr>
                    <td colspan="6" style="text-align:center; padding: 30px; color: var(--risk-low);">
                        ✔️ <strong>Zero Misconfigurations Detected!</strong> Configuration adheres completely to active baseline.
                    </td>
                </tr>`;
        } else {
            data.findings.forEach((f) => {
                const tr = document.createElement("tr");
                const catClass = f.risk_category.toLowerCase();
                
                tr.innerHTML = `
                    <td><strong>${escapeHtml(f.resource_id)}</strong><br><small style="color:var(--text-secondary);">${escapeHtml(f.resource_type)}</small></td>
                    <td><strong>${escapeHtml(f.rule_id)}</strong><br>${escapeHtml(f.rule_name)}</td>
                    <td><span class="pill pill-${catClass}">${escapeHtml(f.risk_category)} (${f.risk_score})</span></td>
                    <td><code>${escapeHtml(f.observed_value)}</code></td>
                    <td style="max-width:250px;">${escapeHtml(f.explanation)}</td>
                    <td>
                        <button class="btn btn-secondary sim-btn" data-rule="${escapeHtml(f.rule_id)}" data-res="${escapeHtml(f.resource_id)}">Simulate Fix</button>
                        <button class="btn btn-secondary view-rule-btn" data-rule="${escapeHtml(f.rule_id)}" style="margin-top:4px;">View Rule</button>
                    </td>
                `;
                findingsTableBody.appendChild(tr);
            });

            document.querySelectorAll(".sim-btn").forEach(btn => {
                btn.addEventListener("click", (e) => openSimModal(e.target.getAttribute("data-rule"), e.target.getAttribute("data-res")));
            });

            document.querySelectorAll(".view-rule-btn").forEach(btn => {
                btn.addEventListener("click", (e) => openRuleDetailModal(e.target.getAttribute("data-rule")));
            });
        }

        resultsContainer.classList.remove("hidden");
    }

    // Load and Render Baseline Rules
    async function loadBaselineRules() {
        try {
            const res = await fetch("/api/baseline");
            const data = await res.json();
            if (data.success && data.rules) {
                allBaselineRules = data.rules;
                renderFilteredBaselineRules();
            }
        } catch (err) {
            console.error("Failed to load baseline rules.");
        }
    }

    function renderFilteredBaselineRules() {
        const query = baselineSearchInput.value.toLowerCase().trim();
        const sevVal = severityFilter.value;

        const filtered = allBaselineRules.filter(r => {
            const matchesQuery = r.id.toLowerCase().includes(query) || 
                                 r.name.toLowerCase().includes(query) || 
                                 (r.applicable_types || []).join(" ").toLowerCase().includes(query);
            
            let matchesSev = true;
            if (sevVal === "CRITICAL") matchesSev = r.severity >= 80;
            else if (sevVal === "HIGH") matchesSev = r.severity >= 60 && r.severity < 80;
            else if (sevVal === "MEDIUM") matchesSev = r.severity >= 35 && r.severity < 60;
            else if (sevVal === "LOW") matchesSev = r.severity < 35;

            return matchesQuery && matchesSev;
        });

        baselineTableBody.innerHTML = "";
        if (filtered.length === 0) {
            baselineTableBody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding: 20px; color: var(--text-secondary);">No baseline rules found matching filter criteria.</td></tr>`;
            return;
        }

        filtered.forEach(r => {
            const tr = document.createElement("tr");
            const catClass = r.severity >= 80 ? "critical" : r.severity >= 60 ? "high" : r.severity >= 35 ? "medium" : "low";
            const typesStr = Array.isArray(r.applicable_types) ? r.applicable_types.join(", ") : r.applicable_types;

            tr.innerHTML = `
                <td><strong>${escapeHtml(r.id)}</strong></td>
                <td>${escapeHtml(r.name)}</td>
                <td><code>${escapeHtml(typesStr)}</code></td>
                <td><code>${escapeHtml(r.property_path || "-")}</code></td>
                <td>${escapeHtml(r.expected_state || "-")}</td>
                <td><span class="pill pill-${catClass}">${r.severity}</span></td>
                <td><small style="color: var(--text-secondary);">${escapeHtml(r.source_reference || "Baseline Standard")}</small></td>
                <td><button class="btn btn-secondary inspect-rule-btn" data-rule="${escapeHtml(r.id)}">Inspect</button></td>
            `;
            baselineTableBody.appendChild(tr);
        });

        document.querySelectorAll(".inspect-rule-btn").forEach(btn => {
            btn.addEventListener("click", (e) => openRuleDetailModal(e.target.getAttribute("data-rule")));
        });
    }

    baselineSearchInput.addEventListener("input", renderFilteredBaselineRules);
    severityFilter.addEventListener("change", renderFilteredBaselineRules);

    // Rule Detail Modal Launcher
    function openRuleDetailModal(ruleId) {
        const rule = allBaselineRules.find(r => r.id === ruleId);
        if (!rule) {
            alert(`Rule ID '${ruleId}' not found in loaded baseline.`);
            return;
        }

        modalRuleTitle.textContent = `Rule Specification: ${rule.id}`;
        modalRuleContent.innerHTML = `
            <div style="display: flex; flex-direction: column; gap: 12px;">
                <div><strong>Rule Name:</strong> ${escapeHtml(rule.name)}</div>
                <div><strong>Severity Score:</strong> <span class="pill pill-${rule.severity >= 80 ? 'critical' : rule.severity >= 60 ? 'high' : 'medium'}">${rule.severity} / 100</span></div>
                <div><strong>Applicable Resource Types:</strong> <code>${escapeHtml((rule.applicable_types || []).join(", "))}</code></div>
                <div><strong>Property Checked:</strong> <code>${escapeHtml(rule.property_path || 'N/A')}</code></div>
                <div><strong>Expected Secure Condition:</strong> <span style="color: var(--risk-low);">${escapeHtml(rule.expected_state)}</span></div>
                <div><strong>Risk Explanation:</strong> <p style="color: var(--text-secondary); margin-top:4px;">${escapeHtml(rule.explanation)}</p></div>
                <div><strong>Remediation Recommendation:</strong> <p style="color: var(--accent-blue); margin-top:4px;">${escapeHtml(rule.remediation)}</p></div>
                <div><strong>Source Standard Reference:</strong> <p style="color: var(--text-secondary); margin-top:4px;"><small>${escapeHtml(rule.source_reference || 'Configured Baseline Policy')}</small></p></div>
            </div>
        `;

        ruleDetailModal.classList.remove("hidden");
    }

    closeRuleModalBtn.addEventListener("click", () => ruleDetailModal.classList.add("hidden"));
    dismissRuleModalBtn.addEventListener("click", () => ruleDetailModal.classList.add("hidden"));

    // Header Toggle Baseline View
    viewBaselineHeaderBtn.addEventListener("click", () => {
        baselineSection.scrollIntoView({ behavior: "smooth" });
    });

    toggleBaselineBtn.addEventListener("click", () => {
        const isHidden = baselineTableBody.parentElement.parentElement.classList.contains("hidden");
        if (isHidden) {
            baselineTableBody.parentElement.parentElement.classList.remove("hidden");
            toggleBaselineBtn.textContent = "Hide Baseline Controls";
        } else {
            baselineTableBody.parentElement.parentElement.classList.add("hidden");
            toggleBaselineBtn.textContent = "Show Baseline Controls";
        }
    });

    // Modal Simulation Logic
    async function openSimModal(ruleId, resourceId) {
        activeSimTarget = { ruleId, resourceId };
        remediationMessage.textContent = `Preparing local simulation for rule ${ruleId} on resource ${resourceId}...`;
        postScanNotice.classList.add("hidden");

        originalConfigPre.textContent = JSON.stringify(activeScanResult.raw_data, null, 2);

        try {
            const res = await fetch("/api/remediate", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    scan_id: currentScanId,
                    rule_id: ruleId,
                    resource_id: resourceId,
                    raw_data: activeScanResult.raw_data,
                    format: activeScanResult.format
                })
            });

            const data = await res.json();
            if (data.success) {
                remediatedConfigPre.textContent = JSON.stringify(data.remediated_data, null, 2);
                remediationMessage.textContent = data.message;
            }
        } catch (err) {
            remediationMessage.textContent = "Error generating simulation preview.";
        }

        remediationModal.classList.remove("hidden");
    }

    closeModalBtn.addEventListener("click", () => remediationModal.classList.add("hidden"));
    dismissModalBtn.addEventListener("click", () => remediationModal.classList.add("hidden"));

    confirmRemediateBtn.addEventListener("click", async () => {
        if (!activeSimTarget) return;
        confirmRemediateBtn.disabled = true;

        try {
            const res = await fetch("/api/remediate", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    scan_id: currentScanId,
                    rule_id: activeSimTarget.ruleId,
                    resource_id: activeSimTarget.resourceId,
                    raw_data: activeScanResult.raw_data,
                    format: activeScanResult.format
                })
            });

            const data = await res.json();
            if (data.success && data.after_scan) {
                postScanNotice.textContent = `Fix applied! Remaining findings in copy: ${data.after_scan.total_findings}. Risk score lowered to ${data.after_scan.overall_risk_score}.`;
                postScanNotice.classList.remove("hidden");
            }
        } catch (err) {
            alert("Remediation execution failed.");
        } finally {
            confirmRemediateBtn.disabled = false;
        }
    });

    // History Table Loader
    async function loadHistory() {
        try {
            const res = await fetch("/api/history");
            const data = await res.json();
            if (data.success && data.history) {
                historyTableBody.innerHTML = "";
                data.history.forEach(h => {
                    const tr = document.createElement("tr");
                    tr.innerHTML = `
                        <td>#${h.scan_id}</td>
                        <td>${h.timestamp}</td>
                        <td>${escapeHtml(h.filename)}</td>
                        <td>${h.format}</td>
                        <td>${h.resources_analyzed}</td>
                        <td>${h.total_findings}</td>
                        <td><strong>${h.overall_risk_score}</strong></td>
                    `;
                    historyTableBody.appendChild(tr);
                });
            }
        } catch (err) {
            console.error("Failed to load history.");
        }
    }

    // Download Reports
    downloadHtmlBtn.addEventListener("click", () => {
        if (currentScanId) window.location.href = `/api/report/html/${currentScanId}`;
    });

    downloadJsonBtn.addEventListener("click", () => {
        if (currentScanId) window.location.href = `/api/report/json/${currentScanId}`;
    });

    function escapeHtml(str) {
        return String(str || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
    }
});