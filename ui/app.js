// Vajra (वज्र) Interactive Security Assistant Frontend Application
// Team: Team_Red_Eagle

let currentIncidents = [];
let selectedIncident = null;
let graphElements = { elements: [] };

// Initialize Canvas
const canvas = document.getElementById("graph-canvas");
const ctx = canvas.getContext("2d");

function resizeCanvas() {
    const container = document.getElementById("graph-container");
    if (!container) return;
    canvas.width = container.clientWidth;
    canvas.height = container.clientHeight;
    drawGraph();
}

window.addEventListener("resize", resizeCanvas);

// Simple Graph Layout & Renderer
function drawGraph() {
    if (!ctx) return;
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const nodes = graphElements.elements.filter(e => e.data && !e.data.source);
    const edges = graphElements.elements.filter(e => e.data && e.data.source);

    if (nodes.length === 0) {
        ctx.fillStyle = "#8ba2c4";
        ctx.font = "14px Inter, sans-serif";
        ctx.textAlign = "center";
        ctx.fillText("Waiting for telemetry events to construct execution lineage graph...", canvas.width / 2, canvas.height / 2);
        return;
    }

    const nodePositions = {};
    const stepX = canvas.width / (nodes.length + 1);

    nodes.forEach((node, idx) => {
        const x = stepX * (idx + 1);
        const y = canvas.height / 2 + ((idx % 2 === 0) ? -40 : 40);
        nodePositions[node.data.id] = { x, y, data: node.data };
    });

    // Draw Edges
    edges.forEach(edge => {
        const src = nodePositions[edge.data.source];
        const tgt = nodePositions[edge.data.target];
        if (src && tgt) {
            ctx.beginPath();
            ctx.moveTo(src.x, src.y);
            ctx.lineTo(tgt.x, tgt.y);
            ctx.strokeStyle = "rgba(79, 172, 254, 0.4)";
            ctx.lineWidth = 2;
            ctx.stroke();

            // Edge label
            const midX = (src.x + tgt.x) / 2;
            const midY = (src.y + tgt.y) / 2 - 8;
            ctx.fillStyle = "#8ba2c4";
            ctx.font = "10px JetBrains Mono, monospace";
            ctx.textAlign = "center";
            ctx.fillText(edge.data.label || "", midX, midY);
        }
    });

    // Draw Nodes
    nodes.forEach(node => {
        const pos = nodePositions[node.data.id];
        if (!pos) return;

        ctx.beginPath();
        ctx.arc(pos.x, pos.y, 22, 0, Math.PI * 2);

        if (pos.data.risk === "critical") {
            ctx.fillStyle = "#ff3366";
            ctx.shadowColor = "rgba(255, 51, 102, 0.6)";
        } else if (pos.data.risk === "high") {
            ctx.fillStyle = "#ff9900";
            ctx.shadowColor = "rgba(255, 153, 0, 0.6)";
        } else {
            ctx.fillStyle = "#00f2fe";
            ctx.shadowColor = "rgba(0, 242, 254, 0.4)";
        }
        ctx.shadowBlur = 12;
        ctx.fill();
        ctx.shadowBlur = 0;

        ctx.strokeStyle = "#fff";
        ctx.lineWidth = 1.5;
        ctx.stroke();

        ctx.fillStyle = "#f0f4fc";
        ctx.font = "11px JetBrains Mono, monospace";
        ctx.textAlign = "center";
        ctx.fillText(pos.data.label || pos.data.id, pos.x, pos.y + 36);

        ctx.fillStyle = "rgba(255, 255, 255, 0.6)";
        ctx.font = "9px Inter, sans-serif";
        ctx.fillText(pos.data.type || "proc", pos.x, pos.y + 48);
    });
}

// Fetch Incidents, Graph Data & Telemetry Overhead
async function refreshState() {
    try {
        const [incRes, graphRes, activeRes, metricRes] = await Promise.all([
            fetch("/v1/incidents"),
            fetch("/v1/graph"),
            fetch("/v1/actions/active"),
            fetch("/v1/metrics/overhead")
        ]);

        if (incRes.ok) {
            currentIncidents = await incRes.json();
            renderIncidentsFeed();
        }

        if (graphRes.ok) {
            graphElements = await graphRes.json();
            drawGraph();
        }

        if (activeRes.ok) {
            const active = await activeRes.json();
            document.getElementById("active-actions").innerHTML = `Active Rollbacks: <strong>${active.length}</strong> (30 min TTL Auto-Reversion)`;
        }

        if (metricRes.ok) {
            const m = await metricRes.json();
            document.getElementById("metric-cpu").innerText = `${m.cpu_overhead_percent}%`;
            document.getElementById("metric-ram").innerText = `${m.memory_rss_mb} MB`;
            document.getElementById("metric-lat").innerText = `${m.event_processing_latency_ms} ms`;
            document.getElementById("metric-drops").innerText = `${m.ring_buffer_drop_rate_percent.toFixed(2)}%`;
        }
    } catch (e) {
        console.warn("Backend poll skipped:", e);
    }
}

function renderIncidentsFeed() {
    const feed = document.getElementById("incidents-feed");
    feed.innerHTML = "";

    if (currentIncidents.length === 0) {
        feed.innerHTML = `<div style="color:var(--text-muted); font-size:0.8rem; text-align:center; padding:1rem;">No incidents recorded yet. Trigger a scenario above to test detection.</div>`;
        return;
    }

    let maxRisk = 0.0;

    [...currentIncidents].reverse().forEach((inc, idx) => {
        const secScore = inc.security_score || 0.0;
        const relScore = inc.reliability_score || 0.0;
        const score = Math.max(secScore, relScore);
        if (score > maxRisk) maxRisk = score;

        const severity = score >= 0.85 ? "critical" : score >= 0.60 ? "high" : score >= 0.30 ? "medium" : "low";
        const evt = inc.event || {};
        const title = `${evt.event_type || "EVENT"} : ${evt.object_value || "unknown"}`;

        const item = document.createElement("div");
        item.className = `incident-item ${severity}`;
        item.innerHTML = `
            <div class="incident-top">
                <span class="incident-title">${title}</span>
                <span class="score-badge ${severity}">${score.toFixed(2)}</span>
            </div>
            <div class="incident-meta">
                Workload: ${evt.workload ? evt.workload.workload_id : "default"} | ID: ${inc.event_id.substring(0, 8)}
            </div>
        `;
        item.onclick = () => selectIncident(inc);
        feed.appendChild(item);

        if (idx === 0 && !selectedIncident) {
            selectIncident(inc);
        }
    });

    const riskEl = document.getElementById("global-risk");
    riskEl.innerText = maxRisk.toFixed(2);
    riskEl.style.color = maxRisk >= 0.85 ? "var(--critical)" : maxRisk >= 0.60 ? "var(--high)" : "var(--low)";
}

function selectIncident(inc) {
    selectedIncident = inc;
    document.getElementById("selected-incident-id").innerText = `INCIDENT: ${inc.event_id}`;

    // Update Counterfactual
    const cf = inc.counterfactual || {};
    document.getElementById("counterfactual-display").innerHTML = `
        <strong>Target Benign Score:</strong> &le; ${cf.target_score || 0.20}<br>
        <strong>Explanation:</strong> ${cf.verbalized_explanation || "No explanation required."}
    `;

    // Update Evidence
    const evDisplay = document.getElementById("evidence-display");
    evDisplay.innerHTML = "";
    const findings = inc.findings || [];
    if (findings.length === 0) {
        evDisplay.innerHTML = `<li>Event conforms to baseline; no rule or statistical violations.</li>`;
    } else {
        findings.forEach(f => {
            (f.evidence || []).forEach(e => {
                const li = document.createElement("li");
                li.innerText = `[${f.finding_id}] ${e}`;
                evDisplay.appendChild(li);
            });
            if (f.mitre_techniques && f.mitre_techniques.length > 0) {
                const liMitre = document.createElement("li");
                liMitre.innerHTML = `<strong style="color:var(--primary);">MITRE ATT&CK:</strong> ${f.mitre_techniques.join(", ")}`;
                evDisplay.appendChild(liMitre);
            }
        });
    }
}

// Download MITRE ATT&CK Navigator Layer JSON
async function downloadMitreLayer() {
    try {
        const res = await fetch("/v1/mitre/navigator");
        if (res.ok) {
            const layerJson = await res.json();
            const blob = new Blob([JSON.stringify(layerJson, null, 2)], { type: "application/json" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = "vajra_mitre_navigator_layer.json";
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }
    } catch (e) {
        alert("Failed to export MITRE Navigator layer: " + e);
    }
}

// Scenarios Execution
async function triggerScenario(type) {
    let payload = {};
    const now = new Date().toISOString();

    if (type === "normal") {
        payload = {
            event_id: "evt-norm-" + Math.floor(Math.random() * 1000),
            observed_at: now,
            host_id: "prod-web-01",
            boot_id: "boot-linux-001",
            event_type: "PROCESS_EXEC",
            subject: { process_id: "boot:1:101", pid: 101, ppid: 1, executable: "/usr/sbin/nginx", uid: 33 },
            object_type: "binary",
            object_value: "/usr/sbin/nginx",
            workload: { workload_id: "nginx.service", environment: "production" },
            result: "success",
            attributes: { baseline_eligible: "true", parent_executable: "/usr/lib/systemd/systemd" },
            trust: { host_attestation: "verified", agent_integrity: "verified", artifact_verification: "verified" }
        };
    } else if (type === "reverse_shell") {
        payload = {
            event_id: "evt-rev-" + Math.floor(Math.random() * 1000),
            observed_at: now,
            host_id: "prod-web-01",
            boot_id: "boot-linux-001",
            event_type: "PROCESS_EXEC",
            subject: { process_id: "boot:1:502", pid: 502, ppid: 101, executable: "/tmp/nc", uid: 33 },
            object_type: "binary",
            object_value: "/tmp/nc",
            workload: { workload_id: "nginx.service", environment: "production" },
            result: "success",
            attributes: { parent_executable: "/usr/sbin/nginx" },
            trust: { host_attestation: "verified", agent_integrity: "verified", artifact_verification: "failed" }
        };
    } else if (type === "lotl") {
        payload = {
            event_id: "evt-lotl-" + Math.floor(Math.random() * 1000),
            observed_at: now,
            host_id: "prod-web-01",
            boot_id: "boot-linux-001",
            event_type: "FILE_ACCESS",
            subject: { process_id: "boot:1:601", pid: 601, ppid: 101, executable: "/usr/bin/curl", uid: 33 },
            object_type: "file",
            object_value: "/etc/shadow",
            workload: { workload_id: "nginx.service", environment: "production" },
            result: "success",
            attributes: { parent_executable: "/usr/sbin/nginx" },
            trust: { host_attestation: "verified", agent_integrity: "verified", artifact_verification: "verified" }
        };
    } else if (type === "memory_leak") {
        payload = {
            event_id: "evt-mem-" + Math.floor(Math.random() * 1000),
            observed_at: now,
            host_id: "prod-web-01",
            boot_id: "boot-linux-001",
            event_type: "RESOURCE_PRESSURE",
            subject: { process_id: "boot:1:101", pid: 101, ppid: 1, executable: "/usr/sbin/nginx", uid: 33 },
            object_type: "cgroup",
            object_value: "/sys/fs/cgroup/system.slice/nginx.service",
            workload: { workload_id: "nginx.service", environment: "production" },
            result: "success",
            attributes: { resource: "memory", pressure_ratio: "0.88", full_pressure_ratio: "0.52", cgroup: "nginx.service" },
            trust: { host_attestation: "verified", agent_integrity: "verified", artifact_verification: "verified" }
        };
    } else if (type === "attestation_fail") {
        payload = {
            event_id: "evt-tpm-" + Math.floor(Math.random() * 1000),
            observed_at: now,
            host_id: "prod-web-01",
            boot_id: "boot-linux-001",
            event_type: "PROCESS_EXEC",
            subject: { process_id: "boot:1:999", pid: 999, ppid: 1, executable: "/usr/bin/sudo", uid: 0 },
            object_type: "binary",
            object_value: "/usr/bin/sudo",
            workload: { workload_id: "system.slice", environment: "production" },
            result: "success",
            attributes: { baseline_eligible: "true" },
            trust: { host_attestation: "failed", agent_integrity: "failed", artifact_verification: "failed" }
        };
        document.getElementById("trust-dot").style.background = "var(--critical)";
        document.getElementById("trust-dot").style.boxShadow = "0 0 8px var(--critical)";
        document.getElementById("trust-state").innerText = "TPM Tampered / Failed";
    }

    try {
        const res = await fetch("/v1/events/assess", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        if (res.ok) {
            await refreshState();
        }
    } catch (e) {
        alert("Error dispatching scenario: " + e);
    }
}

// Chat System
async function sendChat() {
    const input = document.getElementById("chat-input");
    const query = input.value.trim();
    if (!query) return;

    const chatBox = document.getElementById("chat-messages");
    
    // Append User Message
    const userMsg = document.createElement("div");
    userMsg.className = "chat-msg user";
    userMsg.innerText = query;
    chatBox.appendChild(userMsg);
    input.value = "";
    chatBox.scrollTop = chatBox.scrollHeight;

    // Call Assistant API
    try {
        const res = await fetch("/v1/assistant/chat", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ query })
        });
        if (res.ok) {
            const data = await res.json();
            const botMsg = document.createElement("div");
            botMsg.className = "chat-msg assistant";
            let formatted = data.reply
                .replace(/### (.*)/g, '<h4 style="color:var(--primary);margin-bottom:0.4rem;">$1</h4>')
                .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                .replace(/> (.*)/g, '<blockquote style="border-left:2px solid var(--primary);padding-left:0.5rem;margin:0.4rem 0;color:#e0f7fa;">$1</blockquote>');
            botMsg.innerHTML = formatted;
            chatBox.appendChild(botMsg);
            chatBox.scrollTop = chatBox.scrollHeight;
        }
    } catch (e) {
        console.error("Chat error:", e);
    }
}

function handleChatKey(event) {
    if (event.key === "Enter") {
        sendChat();
    }
}

// Remediation Execution
async function executeAction(actionType) {
    if (!selectedIncident) {
        alert("Please select an incident first.");
        return;
    }
    const target = selectedIncident.event ? selectedIncident.event.workload.workload_id : "nginx.service";
    try {
        const res = await fetch("/v1/actions/execute", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                action_type: actionType,
                target: target,
                analyst_approved: true
            })
        });
        if (res.ok) {
            const data = await res.json();
            alert(`✅ ${data.message}`);
            await refreshState();
        }
    } catch (e) {
        alert("Action execution error: " + e);
    }
}

// Polling interval for live sync
setInterval(refreshState, 3000);
window.onload = () => {
    resizeCanvas();
    refreshState();
};
