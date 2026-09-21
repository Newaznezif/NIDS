/**
 * NIDS SOC Security Dashboard Controller
 * Handles REST API calls, Socket.IO real-time feed, Chart.js graphs, and demo controls.
 */

document.addEventListener("DOMContentLoaded", () => {
    // API Configuration
    const API_BASE = ""; // Relative path when served from Flask

    // DOM Elements
    const metricAttacks = document.getElementById("metric-total-attacks");
    const metricThreats = document.getElementById("metric-active-threats");
    const metricAlerts = document.getElementById("metric-total-alerts");
    const metricPackets = document.getElementById("metric-packets");
    const metricRate = document.getElementById("metric-rate");

    const modeBadge = document.getElementById("mode-status-badge");
    const modeText = document.getElementById("mode-status-text");
    const connBadge = document.getElementById("connection-badge");
    const connText = document.getElementById("connection-status-text");

    const tableBody = document.getElementById("alerts-table-body");
    const alertsCountBadge = document.getElementById("alerts-count-badge");
    const alertSearchInput = document.getElementById("alert-search");
    const severityFilterSelect = document.getElementById("severity-filter");

    const btnPortScan = document.getElementById("btn-demo-portscan");
    const btnSynFlood = document.getElementById("btn-demo-synflood");
    const btnRefresh = document.getElementById("btn-refresh");
    const btnClear = document.getElementById("btn-clear");

    // Asset monitoring controls + status
    const assetIpInput = document.getElementById("asset-ip-input");
    const assetModeSelect = document.getElementById("asset-mode-select");
    const btnStartMonitor = document.getElementById("btn-start-monitor");
    const btnStopMonitor = document.getElementById("btn-stop-monitor");
    const monitorAsset = document.getElementById("monitor-asset");
    const monitorInterface = document.getElementById("monitor-interface");
    const monitorCaptureState = document.getElementById("monitor-capture-state");
    const monitorAssetPackets = document.getElementById("monitor-asset-packets");
    const monitorFlows = document.getElementById("monitor-flows");

    // Global State
    let allAlerts = [];
    let socket = null;
    let isPolling = false;
    let pollingInterval = null;

    // Chart Instances
    let timelineChart, typesChart, severityChart, topAttackersChart;

    // --- 1. INITIALIZATION & CHARTS ---
    initCharts();
    setupThemeToggle();
    fetchStats();
    fetchAlerts();
    fetchMonitorStatus();
    setupSocket();
    setupEventListeners();

    // Setup periodic polling fallback every 3s
    startPolling();

    // --- 2. SOCKET.IO REALTIME SETUP ---
    function setupSocket() {
        try {
            socket = io(window.location.origin, {
                reconnection: true,
                reconnectionDelay: 1000,
                reconnectionAttempts: 10,
                timeout: 5000
            });

            socket.on("connect", () => {
                console.log("[SOCKET] Connected to real-time NIDS server.");
                updateConnectionBadge("CONNECTED", "status-connected", "Live Feed Active");
            });

            socket.on("disconnect", () => {
                console.warn("[SOCKET] Disconnected. Polling fallback active.");
                updateConnectionBadge("POLLING", "status-connecting", "Polling Fallback");
            });

            socket.on("new_alert", (alertData) => {
                console.log("[SOCKET EVENT] New alert received:", alertData);
                onNewAlertReceived(alertData);
            });

            socket.on("stats_update", (statsData) => {
                updateDashboardMetrics(statsData);
            });
        } catch (e) {
            console.error("Socket.IO setup failed:", e);
            updateConnectionBadge("POLLING", "status-connecting", "Polling Fallback");
        }
    }

    function updateConnectionBadge(state, cssClass, label) {
        connBadge.className = `status-pill ${cssClass}`;
        connText.textContent = label;
    }

    function startPolling() {
        if (!pollingInterval) {
            pollingInterval = setInterval(() => {
                fetchStats();
                fetchAlerts(true); // silent fetch
                fetchMonitorStatus();
            }, 3000);
        }
    }

    // --- 3. API FETCH FUNCTIONS ---
    async function fetchStats() {
        try {
            const res = await fetch(`${API_BASE}/api/stats`);
            if (!res.ok) return;
            const data = await res.json();
            updateDashboardMetrics(data);
        } catch (err) {
            console.error("Error fetching stats:", err);
        }
    }

    async function fetchAlerts(silent = false) {
        try {
            const res = await fetch(`${API_BASE}/api/alerts?limit=100`);
            if (!res.ok) return;
            const data = await res.json();
            allAlerts = data.alerts || [];
            renderAlertsTable();
            updateTimelineChart(); // recent activity only; aggregates come from /api/stats
        } catch (err) {
            console.error("Error fetching alerts:", err);
        }
    }

    async function fetchMonitorStatus() {
        try {
            const res = await fetch(`${API_BASE}/api/monitor/status`);
            if (!res.ok) return;
            const data = await res.json();
            renderMonitorStatus(data);
        } catch (err) {
            console.error("Error fetching monitor status:", err);
        }
    }

    function renderMonitorStatus(m) {
        const asset = (m.asset && m.asset.asset_ip) || "none";
        const mode = (m.asset && m.asset.mode) || "BOTH";
        monitorAsset.textContent = (asset === "none") ? "none" : `${asset} (${mode})`;
        monitorInterface.textContent = m.interface || "-";
        monitorAssetPackets.textContent = (m.asset_packets_observed ?? 0).toLocaleString();
        monitorFlows.textContent = (m.flows_total ?? 0).toLocaleString();

        // Honest capture state: LIVE only while packets are actually arriving.
        const state = m.capture_state || "UNKNOWN";
        monitorCaptureState.textContent = state;
        monitorCaptureState.style.color = (state === "LIVE") ? "var(--accent-emerald)" : "var(--accent-amber, #f59e0b)";
        updateModeBadge(state, !!(m.asset && m.asset.enabled));
    }

    function updateModeBadge(state, assetEnabled) {
        if (state === "LIVE" && assetEnabled) {
            // Sensor is receiving packets AND an asset is actually scoped.
            modeBadge.className = "status-pill status-live";
            modeText.textContent = "LIVE MONITORING";
        } else if (state === "LIVE") {
            // Sensor is live but no asset is being monitored; do not claim asset monitoring.
            modeBadge.className = "status-pill status-demo";
            modeText.textContent = "CAPTURE LIVE";
        } else {
            modeBadge.className = "status-pill status-demo";
            modeText.textContent = state; // NO_TRAFFIC / CAPTURE_ERROR / PERMISSION_DENIED / etc.
        }
    }

    // --- 4. UI METRIC & MODE UPDATES ---
    function updateDashboardMetrics(stats) {
        metricAttacks.textContent = stats.total_attacks ?? 0;
        metricThreats.textContent = stats.active_threats ?? 0;
        metricAlerts.textContent = stats.total_alerts ?? 0;
        metricPackets.textContent = (stats.total_packets ?? 0).toLocaleString();
        metricRate.textContent = stats.detection_rate ?? "0.0%";

        // Aggregate charts reflect the FULL database via get_stats(), keeping them
        // consistent with the metric cards (the alert feed is capped at the last 100).
        updateAggregateCharts(stats);

        // Capture-state badge reflects the honest capture state, not a static LIVE/DEMO.
        updateModeBadge(stats.capture_state || stats.mode || "UNKNOWN", !!(stats.asset && stats.asset.enabled));
    }

    function onNewAlertReceived(alert) {
        // Unshift to list if not already present
        if (!allAlerts.some(a => a.id === alert.id)) {
            allAlerts.unshift(alert);
            renderAlertsTable();
            fetchStats();
        }
    }

    // --- 5. RENDER ALERTS TABLE ---
    function renderAlertsTable() {
        const searchTerm = alertSearchInput.value.toLowerCase().trim();
        const severityFilter = severityFilterSelect.value;

        const filtered = allAlerts.filter(alert => {
            const matchesSearch =
                !searchTerm ||
                (alert.source_ip || '').toLowerCase().includes(searchTerm) ||
                (alert.destination_ip || '').toLowerCase().includes(searchTerm) ||
                (alert.attack_type || '').toLowerCase().includes(searchTerm) ||
                (alert.details && alert.details.toLowerCase().includes(searchTerm));

            const matchesSeverity = (severityFilter === "ALL") || (alert.severity === severityFilter);

            return matchesSearch && matchesSeverity;
        });

        alertsCountBadge.textContent = `${filtered.length} Events`;

        if (filtered.length === 0) {
            const emptyMsg = (allAlerts.length === 0)
                ? 'No security alerts recorded yet. Live traffic is being monitored; use the panel above to simulate an attack.'
                : 'No security alerts match the current filter.';
            tableBody.innerHTML = `
                <tr>
                    <td colspan="12" class="empty-state">
                        <i class="fa-solid fa-shield-cat"></i>
                        <p>${emptyMsg}</p>
                    </td>
                </tr>
            `;
            return;
        }

        tableBody.innerHTML = filtered.map(alert => {
            const sevClass = getSeverityBadgeClass(alert.severity);
            const formattedTime = formatTimestamp(alert.timestamp);
            const srcIp = escapeHtml(alert.source_ip || '');
            const dstIp = escapeHtml(alert.destination_ip || '');
            const attackType = escapeHtml(alert.attack_type || '');
            const protocol = escapeHtml(alert.protocol || 'TCP');
            const status = escapeHtml(alert.status || 'ACTIVE');
            const severity = escapeHtml(alert.severity || '');
            const rawTs = escapeHtml(alert.timestamp || '');
            const assetIp = escapeHtml(alert.asset_ip || '-');
            const evidence = escapeHtml(formatEvidence(alert.evidence));

            return `
                <tr>
                    <td class="mono-cell">#${alert.id || '-'}</td>
                    <td class="mono-cell" title="${rawTs}">${escapeHtml(formattedTime)}</td>
                    <td><span class="severity-badge ${sevClass}">${severity}</span></td>
                    <td style="font-weight: 600; color: var(--text-primary);">${attackType}</td>
                    <td class="mono-cell">${srcIp}${alert.source_port ? ':' + escapeHtml(alert.source_port) : ''}</td>
                    <td class="mono-cell">${dstIp}${alert.destination_port ? ':' + escapeHtml(alert.destination_port) : ''}</td>
                    <td class="mono-cell">${protocol}</td>
                    <td class="mono-cell">${Math.round((alert.confidence || 0.9) * 100)}%</td>
                    <td><span style="color: var(--accent-emerald); font-weight: 600; font-size: 0.75rem;">${status}</span></td>
                    <td class="mono-cell">${assetIp}</td>
                    <td class="mono-cell" style="font-size: 0.72rem;" title="${evidence}">${evidence}</td>
                    <td style="max-width: 250px; font-size: 0.78rem;" title="${escapeHtml(alert.details || '')}">${escapeHtml(alert.details || 'N/A')}</td>
                </tr>
            `;
        }).join("");
    }

    function formatEvidence(ev) {
        if (!ev || typeof ev !== 'object') return '-';
        const parts = [];
        if (ev.unique_ports !== undefined) parts.push(`ports=${ev.unique_ports}`);
        if (Array.isArray(ev.ports) && ev.ports.length) parts.push(`[${ev.ports.slice(0, 8).join(',')}${ev.ports.length > 8 ? '…' : ''}]`);
        if (ev.syn_count !== undefined) parts.push(`syn=${ev.syn_count}`);
        if (ev.packet_count !== undefined) parts.push(`pkts=${ev.packet_count}`);
        if (ev.observed_rate_per_sec !== undefined) parts.push(`rate=${ev.observed_rate_per_sec}/s`);
        if (ev.window_seconds !== undefined) parts.push(`win=${ev.window_seconds}s`);
        if (ev.threshold !== undefined) parts.push(`thr=${ev.threshold}`);
        if (ev.reason) parts.push(ev.reason);
        return parts.length ? parts.join(' ') : '-';
    }

    function getSeverityBadgeClass(sev) {
        switch (String(sev).toUpperCase()) {
            case "CRITICAL": return "sev-critical";
            case "HIGH": return "sev-high";
            case "MEDIUM": return "sev-medium";
            case "LOW": return "sev-low";
            default: return "sev-medium";
        }
    }

    function formatTimestamp(tsStr) {
        if (!tsStr) return "";
        try {
            const date = new Date(tsStr);
            return date.toLocaleTimeString();
        } catch (e) {
            return tsStr;
        }
    }

    function escapeHtml(str) {
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    // --- 6. CHART.JS VISUALIZATIONS ---
    // Semantic severity scale (shared with the workbench design system):
    // CRITICAL red, HIGH orange, MEDIUM amber, LOW green.
    const SEV_COLORS = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#f59e0b', LOW: '#22c55e' };

    function chartTheme() {
        const light = document.documentElement.getAttribute('data-theme') === 'light';
        return {
            text: light ? '#475569' : '#94a3b8',
            grid: light ? 'rgba(15, 23, 42, 0.08)' : 'rgba(255, 255, 255, 0.05)',
        };
    }

    function initCharts() {
        const T = chartTheme();
        Chart.defaults.color = T.text;
        Chart.defaults.font.family = "'Outfit', sans-serif";
        const GRID = T.grid;

        // Timeline Chart (Attacks Over Time)
        const ctxTimeline = document.getElementById('chart-timeline').getContext('2d');
        timelineChart = new Chart(ctxTimeline, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Attacks Count',
                    data: [],
                    borderColor: '#00f2fe',
                    backgroundColor: 'rgba(0, 242, 254, 0.1)',
                    fill: true,
                    tension: 0.3,
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { color: GRID } },
                    y: { grid: { color: GRID }, beginAtZero: true, ticks: { precision: 0 } }
                }
            }
        });

        // Attack Types Chart (Doughnut)
        const ctxTypes = document.getElementById('chart-attack-types').getContext('2d');
        typesChart = new Chart(ctxTypes, {
            type: 'doughnut',
            data: {
                labels: ['PORT_SCAN', 'SYN_FLOOD', 'SUSPICIOUS_PORT'],
                datasets: [{
                    data: [0, 0, 0],
                    backgroundColor: ['#00f2fe', '#f59e0b', '#8b5cf6', '#ef4444'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'right' } }
            }
        });

        // Severity Distribution Chart (Bar)
        const ctxSeverity = document.getElementById('chart-severity').getContext('2d');
        severityChart = new Chart(ctxSeverity, {
            type: 'bar',
            data: {
                labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: [SEV_COLORS.CRITICAL, SEV_COLORS.HIGH, SEV_COLORS.MEDIUM, SEV_COLORS.LOW],
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { display: false } },
                    y: { grid: { color: GRID }, beginAtZero: true, ticks: { precision: 0 } }
                }
            }
        });

        // Top Attacker IPs Chart (Horizontal Bar)
        const ctxAttackers = document.getElementById('chart-top-attackers').getContext('2d');
        topAttackersChart = new Chart(ctxAttackers, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Attacks Triggered',
                    data: [],
                    backgroundColor: 'rgba(239, 68, 68, 0.7)',
                    borderColor: '#ef4444',
                    borderWidth: 1,
                    borderRadius: 4
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { color: GRID }, beginAtZero: true, ticks: { precision: 0 } },
                    y: { grid: { display: false } }
                }
            }
        });
    }

    // Re-skin existing charts when the appearance changes (no data reload).
    function applyChartTheme() {
        const T = chartTheme();
        Chart.defaults.color = T.text;
        [timelineChart, typesChart, severityChart, topAttackersChart].forEach((c) => {
            if (!c) return;
            const scales = c.options.scales || {};
            Object.values(scales).forEach((s) => { if (s && s.grid && s.grid.color !== undefined && s.grid.display !== false) s.grid.color = T.grid; });
            c.update();
        });
    }

    function setupThemeToggle() {
        if (!window.NIDSTheme) return;
        NIDSTheme.init();
        const btn = document.getElementById('btn-theme');
        const label = document.getElementById('theme-mode-text');
        const order = ['system', 'light', 'dark'];
        const pretty = { system: 'System', light: 'Light', dark: 'Dark' };
        const sync = () => { if (label) label.textContent = pretty[NIDSTheme.current()] || 'System'; };
        NIDSTheme.onChange(applyChartTheme);
        NIDSTheme.onChange(sync);
        sync();
        if (btn) btn.onclick = () => {
            const next = order[(order.indexOf(NIDSTheme.current()) + 1) % order.length];
            NIDSTheme.apply(next);
        };
    }

    // Aggregate charts are sourced from /api/stats (full DB), never fabricated.
    function updateAggregateCharts(stats) {
        if (!stats) return;

        // 1. Attack Categories (doughnut) — from stats.attack_types
        const typeEntries = Object.entries(stats.attack_types || {});
        typesChart.data.labels = typeEntries.map(e => e[0]);
        typesChart.data.datasets[0].data = typeEntries.map(e => e[1]);
        typesChart.update();

        // 2. Severity Breakdown (bar) — from stats.severity_distribution
        const sev = stats.severity_distribution || {};
        severityChart.data.datasets[0].data = [
            sev.CRITICAL || 0,
            sev.HIGH || 0,
            sev.MEDIUM || 0,
            sev.LOW || 0
        ];
        severityChart.update();

        // 3. Top Attacker IPs (horizontal bar) — from stats.top_attackers
        const attackers = stats.top_attackers || [];
        topAttackersChart.data.labels = attackers.map(a => a.ip);
        topAttackersChart.data.datasets[0].data = attackers.map(a => a.count);
        topAttackersChart.update();
    }

    // Timeline reflects recent alert activity (last fetched window of alerts).
    function updateTimelineChart() {
        if (!allAlerts) return;
        const timeBucket = {};
        allAlerts.slice().reverse().forEach(alert => {
            const timeStr = formatTimestamp(alert.timestamp);
            timeBucket[timeStr] = (timeBucket[timeStr] || 0) + 1;
        });

        const timelineLabels = Object.keys(timeBucket).slice(-15);
        const timelineValues = timelineLabels.map(l => timeBucket[l]);

        timelineChart.data.labels = timelineLabels;
        timelineChart.data.datasets[0].data = timelineValues;
        timelineChart.update();
    }

    // --- 7. DEMO ATTACK TRIGGERS ---
    function setupEventListeners() {
        btnPortScan.addEventListener("click", async () => {
            btnPortScan.disabled = true;
            btnPortScan.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Scanning...`;
            
            try {
                const res = await fetch(`${API_BASE}/api/demo/attack`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ attack_type: "PORT_SCAN", ports_count: 10 })
                });
                const data = await res.json();
                console.log("Port scan result:", data);
                await fetchAlerts();
                await fetchStats();
            } catch (err) {
                alert("Failed to execute Port Scan demo: " + err.message);
            } finally {
                btnPortScan.disabled = false;
                btnPortScan.innerHTML = `<i class="fa-solid fa-radar"></i> Simulate Port Scan`;
            }
        });

        btnSynFlood.addEventListener("click", async () => {
            btnSynFlood.disabled = true;
            btnSynFlood.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Flooding...`;

            try {
                const res = await fetch(`${API_BASE}/api/demo/attack`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ attack_type: "SYN_FLOOD" })
                });
                const data = await res.json();
                console.log("SYN flood result:", data);
                await fetchAlerts();
                await fetchStats();
            } catch (err) {
                alert("Failed to execute SYN Flood demo: " + err.message);
            } finally {
                btnSynFlood.disabled = false;
                btnSynFlood.innerHTML = `<i class="fa-solid fa-bolt"></i> Simulate SYN Flood`;
            }
        });

        btnRefresh.addEventListener("click", () => {
            fetchStats();
            fetchAlerts();
        });

        btnClear.addEventListener("click", async () => {
            if (!confirm("Are you sure you want to clear all alerts and reset stats?")) return;
            try {
                await fetch(`${API_BASE}/api/clear`, { method: "POST" });
                allAlerts = [];
                renderAlertsTable();
                fetchStats();
            } catch (err) {
                alert("Failed to clear system data: " + err.message);
            }
        });

        alertSearchInput.addEventListener("input", renderAlertsTable);
        severityFilterSelect.addEventListener("change", renderAlertsTable);

        btnStartMonitor.addEventListener("click", async () => {
            const assetIp = assetIpInput.value.trim();
            const mode = assetModeSelect.value;
            if (!assetIp) { alert("Enter an Asset IP to monitor."); return; }
            btnStartMonitor.disabled = true;
            try {
                const res = await fetch(`${API_BASE}/api/monitor/start`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ asset_ip: assetIp, mode })
                });
                const data = await res.json();
                if (!res.ok) { alert("Failed to start monitoring: " + (data.error || res.status)); return; }
                await fetchMonitorStatus();
                await fetchStats();
            } catch (err) {
                alert("Failed to start monitoring: " + err.message);
            } finally {
                btnStartMonitor.disabled = false;
            }
        });

        btnStopMonitor.addEventListener("click", async () => {
            try {
                await fetch(`${API_BASE}/api/monitor/stop`, { method: "POST" });
                await fetchMonitorStatus();
            } catch (err) {
                alert("Failed to stop monitoring: " + err.message);
            }
        });
    }
});
