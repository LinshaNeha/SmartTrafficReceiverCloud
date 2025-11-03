// ===== Global Variables =====
let trafficData = [];
let charts = {}; // store all chart instances

// ===== Fetch JSON from backend (raw data only) =====
async function fetchTrafficData() {
    try {
        const [res1, res2] = await Promise.all([
            fetch("/get_traffic_data"),
            fetch("/receive_plain_data")
        ]);

        const raw1 = await res1.json();
        const raw2 = await res2.json();

        // flatten and normalize
        let allLogs = [
            ...(raw1.decrypted || []),
            ...(raw1.received || []),
            ...(raw2.plain || [])
        ];

        trafficData = allLogs.map(entry => {
            const d = entry.data || {};
            return {
                type: entry.type || "unknown",
                data: {
                    timestamp: d.Timestamp || d.timestamp || "",
                    src_ip: d["Source IP"] || d.src_ip || "",
                    dst_ip: d["Destination IP"] || d.dst_ip || "",
                    src_port: d["Source Port"] || d.src_port || "",
                    dst_port: d["Destination Port"] || d.dst_port || "",
                    protocol: d.Protocol || d.protocol || "Unknown",
                    packet_size: d["Packet Size"] || d.packet_size || 0,
                    flow_duration: d["Flow Duration"] || d.flow_duration || 0,
                    traffic_type: d["Traffic Type"] || d.traffic_type || "Other",
                    attack_cat: d.attack_cat ? d.attack_cat : (d.label === 1 ? "Attack" : "Normal"),
                    label: d.label !== undefined ? d.label : (d.attack_cat && d.attack_cat.toLowerCase() !== "normal" ? 1 : 0),
                    severity: d.Severity || d.severity || "Low",
                    system_health: d["System Health"] || d.system_health || "OK",
                    status: d.Status || d.status || "Open"
                }
            };
        });

        console.log("✅ Normalized trafficData:", trafficData);
        // NOTE: UI updates now handled inside traffic.html and ids.html
    } catch (err) {
        console.error("Error fetching data:", err);
    }
}

// ===== Fetch QKD Status (used by index.html) =====
async function fetchQKDStatus() {
    try {
        const res = await fetch("/get_qkd_status");
        const data = await res.json();
        const qkdStatusEl = document.getElementById("qkdStatusCard");

        if (qkdStatusEl) {
            if (data.status === "Active") {
                qkdStatusEl.textContent = "✅ Received";
                qkdStatusEl.style.color = "green";
            } else {
                qkdStatusEl.textContent = "⏳ Idle";
                qkdStatusEl.style.color = "gray";
            }
        }
    } catch (err) {
        console.error("Error checking QKD status:", err);
        const qkdStatusEl = document.getElementById("qkdStatusCard");
        if (qkdStatusEl) qkdStatusEl.textContent = "❌ Error";
    }
}

// ===== Unlock & Fetch QKD Key (used by qkd.html) =====
async function unlockQKDKey() {
    try {
        const res = await fetch("/get_qkd_key");
        const data = await res.json();
        const keyEl = document.getElementById("qkdKeyDisplay");

        if (keyEl) {
            if (data.key) {
                keyEl.textContent = "🔑 " + data.key;
                keyEl.style.color = "lightgreen";
            } else {
                keyEl.textContent = "❌ No key available";
                keyEl.style.color = "red";
            }
        }
    } catch (err) {
        console.error("Error unlocking QKD key:", err);
        const keyEl = document.getElementById("qkdKeyDisplay");
        if (keyEl) {
            keyEl.textContent = "❌ Error unlocking key";
            keyEl.style.color = "red";
        }
    }
}

// ===== QKD Logs (used by qkd.html) =====
async function fetchQKDLogs() {
    try {
        const res = await fetch("/get_qkd_logs");
        const data = await res.json();
        const logsEl = document.getElementById("qkdLogs");

        if (logsEl) logsEl.textContent = data.logs.join("\n");
    } catch (err) {
        console.error("Error fetching QKD logs:", err);
        const logsEl = document.getElementById("qkdLogs");
        if (logsEl) logsEl.textContent = "❌ Error fetching logs";
    }
}

// ===== Chart Helper =====
function updateChart(id, type, labels, data, colors = null) {
    const ctx = document.getElementById(id);
    if (!ctx) return;
    const context = ctx.getContext("2d");

    if (charts[id]) {
        charts[id].data.labels = labels;
        charts[id].data.datasets[0].data = data;
        if (colors) charts[id].data.datasets[0].backgroundColor = colors;
        charts[id].update();
    } else {
        charts[id] = new Chart(context, {
            type: type,
            data: {
                labels: labels,
                datasets: [{ 
                    data: data, 
                    backgroundColor: colors || ["#3498db", "#9b59b6", "#f1c40f", "#2ecc71"] 
                }]
            }
        });
    }
}

// ===== Gauge Helper =====
function updateGauge(id, label, value) {
    updateChart(id, "doughnut", [label, ""], [value, 100 - value], ["#2980b9", "#ecf0f1"]);
}

// =============================
// Auto-refresh (every 5 seconds)
// =============================
function refreshAll() {
    fetchQKDStatus();
    fetchQKDLogs();
    // trafficData refresh can be triggered manually in traffic.html / ids.html
}

refreshAll();
setInterval(refreshAll, 5000);
