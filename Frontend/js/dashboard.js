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

    // Global State
    let allAlerts = [];
    let socket = null;
    let isPolling = false;
    let pollingInterval = null;

    // Chart Instances
    let timelineChart, typesChart, severityChart, topAttackersChart;

    // --- 1. INITIALIZATION & CHARTS ---
    initCharts();
    fetchStats();
    fetchAlerts();
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
            updateChartsData();
        } catch (err) {
            console.error("Error fetching alerts:", err);
        }
    }

    // --- 4. UI METRIC & MODE UPDATES ---
    function updateDashboardMetrics(stats) {
        metricAttacks.textContent = stats.total_attacks ?? 0;
        metricThreats.textContent = stats.active_threats ?? 0;
        metricAlerts.textContent = stats.total_alerts ?? 0;
        metricPackets.textContent = (stats.total_packets ?? 0).toLocaleString();
        metricRate.textContent = stats.detection_rate ?? "0.0%";

        // Update Mode Badge
        const mode = (stats.mode || "DEMO").toUpperCase();
        if (mode === "LIVE") {
            modeBadge.className = "status-pill status-live";
            modeText.textContent = "LIVE MONITORING";
        } else {
            modeBadge.className = "status-pill status-demo";
            modeText.textContent = `DEMO MODE (${stats.sniffer_status?.mode || "SIMULATED"})`;
        }
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
                alert.source_ip.toLowerCase().includes(searchTerm) ||
                alert.destination_ip.toLowerCase().includes(searchTerm) ||
                alert.attack_type.toLowerCase().includes(searchTerm) ||
                (alert.details && alert.details.toLowerCase().includes(searchTerm));

            const matchesSeverity = (severityFilter === "ALL") || (alert.severity === severityFilter);

            return matchesSearch && matchesSeverity;
        });

        alertsCountBadge.textContent = `${filtered.length} Events`;

        if (filtered.length === 0) {
            tableBody.innerHTML = `
                <tr>
                    <td colspan="10" class="empty-state">
                        <i class="fa-solid fa-shield-cat"></i>
                        <p>No security alerts match the current filter.</p>
                    </td>
                </tr>
            `;
            return;
        }

        tableBody.innerHTML = filtered.map(alert => {
            const sevClass = getSeverityBadgeClass(alert.severity);
            const formattedTime = formatTimestamp(alert.timestamp);

            return `
                <tr>
                    <td class="mono-cell">#${alert.id || '-'}</td>
                    <td class="mono-cell" title="${alert.timestamp}">${formattedTime}</td>
                    <td><span class="severity-badge ${sevClass}">${alert.severity}</span></td>
                    <td style="font-weight: 600; color: #f8fafc;">${alert.attack_type}</td>
                    <td class="mono-cell">${alert.source_ip}${alert.source_port ? ':' + alert.source_port : ''}</td>
                    <td class="mono-cell">${alert.destination_ip}${alert.destination_port ? ':' + alert.destination_port : ''}</td>
                    <td class="mono-cell">${alert.protocol || 'TCP'}</td>
                    <td class="mono-cell">${Math.round((alert.confidence || 0.9) * 100)}%</td>
                    <td><span style="color: var(--accent-emerald); font-weight: 600; font-size: 0.75rem;">${alert.status || 'ACTIVE'}</span></td>
                    <td style="max-width: 250px; font-size: 0.78rem;" title="${escapeHtml(alert.details || '')}">${escapeHtml(alert.details || 'N/A')}</td>
                </tr>
            `;
        }).join("");
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
    function initCharts() {
        Chart.defaults.color = '#94a3b8';
        Chart.defaults.font.family = "'Outfit', sans-serif";

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
                    x: { grid: { color: 'rgba(255, 255, 255, 0.05)' } },
                    y: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, beginAtZero: true, ticks: { precision: 0 } }
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
                    backgroundColor: ['#ef4444', '#f59e0b', '#8b5cf6', '#00f2fe'],
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { display: false } },
                    y: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, beginAtZero: true, ticks: { precision: 0 } }
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
                    x: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, beginAtZero: true, ticks: { precision: 0 } },
                    y: { grid: { display: false } }
                }
            }
        });
    }

    function updateChartsData() {
        if (!allAlerts) return;

        // 1. Attack Types Breakdown
        const typeCounts = {};
        const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
        const ipCounts = {};

        allAlerts.forEach(alert => {
            // Types
            typeCounts[alert.attack_type] = (typeCounts[alert.attack_type] || 0) + 1;
            // Severity
            if (sevCounts.hasOwnProperty(alert.severity)) {
                sevCounts[alert.severity]++;
            }
            // IPs
            ipCounts[alert.source_ip] = (ipCounts[alert.source_ip] || 0) + 1;
        });

        // Update Doughnut Chart
        typesChart.data.labels = Object.keys(typeCounts);
        typesChart.data.datasets[0].data = Object.values(typeCounts);
        typesChart.update();

        // Update Severity Bar Chart
        severityChart.data.datasets[0].data = [
            sevCounts.CRITICAL,
            sevCounts.HIGH,
            sevCounts.MEDIUM,
            sevCounts.LOW
        ];
        severityChart.update();

        // Update Top Attackers Chart
        const sortedIPs = Object.entries(ipCounts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5);
        topAttackersChart.data.labels = sortedIPs.map(item => item[0]);
        topAttackersChart.data.datasets[0].data = sortedIPs.map(item => item[1]);
        topAttackersChart.update();

        // Update Timeline Chart (Grouped by minute)
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
    }
});
