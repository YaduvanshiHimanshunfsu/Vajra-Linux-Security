# ⚡ वज्र (Vajra) — System Architecture Diagram Specification
**Project**: `7. वज्र (Vajra)` | **Team**: `Team_Red_Eagle`  
**Problem Statement**: *AI-Powered Explainable Linux Security Assistant for Kernel-Level Intrusion & Behavioral Threat Detection*

---

## 🎯 Architecture Overview

This document provides the complete structural architecture and data-flow diagrams for **वज्र (Vajra)**. You can copy the Mermaid code below into [mermaid.live](https://mermaid.live) or your markdown previewer to export an official high-resolution **PNG/JPEG (under 300KB)** for your hackathon submission.

---

## 📊 1. End-to-End System Architecture Diagram

```mermaid
flowchart TB
    %% STYLING
    classDef sensing fill:#1a233a,stroke:#00f2fe,stroke-width:2px,color:#e0f7fa;
    classDef aiCore fill:#201c38,stroke:#a855f7,stroke-width:2px,color:#f3e8ff;
    classDef graphXai fill:#112a2e,stroke:#10b981,stroke-width:2px,color:#ecfdf5;
    classDef soar fill:#3b1824,stroke:#ff3366,stroke-width:2px,color:#ffe4e6;
    classDef uiLayer fill:#1e293b,stroke:#38bdf8,stroke-width:2px,color:#f0f9ff;
    classDef hardware fill:#292524,stroke:#f59e0b,stroke-width:2px,color:#fef3c7;

    %% HARDWARE LAYER
    subgraph L0 ["0. Hardware Trust & Integrity Root"]
        TPM["TPM 2.0 Quote Attestation<br/>(PCR 0-7 Host Verification)"]:::hardware
        IMA["IMA Runtime Integrity<br/>(Binary & Config Hash Ledger)"]:::hardware
    end

    %% LAYER 1: SENSING
    subgraph L1 ["1. Kernel Telemetry & Dual-Mode Ingestion Layer"]
        BPF_EXEC["eBPF sched_process_exec<br/>(Task Dentry & Parent PPID)"]:::sensing
        BPF_VFS["eBPF vfs_write / openat2<br/>(Sensitive Decoy File Access)"]:::sensing
        BPF_SOCK["eBPF tcp_v4_connect<br/>(Egress C2 & Sockets)"]:::sensing
        PSI_STREAM["Linux PSI Engine<br/>(/proc/pressure/{mem,cpu,io})"]:::sensing
        REPLAY["Dual-Mode Replay Sensor<br/>(Deterministic Test Engine)"]:::sensing
    end

    %% LAYER 2: AI CORE
    subgraph L2 ["2. AI Behavioral & Risk Fusion Core"]
        MARKOV["Laplace Markov Transition Model<br/>I(u → v) = -log2 P̂(v|u, Wk)"]:::aiCore
        PSI_EWMA["PSI Failure Forecaster<br/>EWMA μ, σ² & Velocity ΔP/Δt"]:::aiCore
        RULE_ENG["Policy Rule Engine<br/>(YAML Prefix & Path Matching)"]:::aiCore
        NOISY_OR["Bayesian Noisy-OR Fusion<br/>R = 1 - ∏(1 - si) ∈ [0, 1]"]:::aiCore
    end

    %% LAYER 3: XAI & PROVENANCE
    subgraph L3 ["3. Causal Provenance & Explainability (XAI) Engine"]
        PROV_DAG["In-Memory Causal Lineage DAG<br/>(Process → File → Socket)"]:::graphXai
        CF_SOLVER["L0 Minimal Counterfactual Solver<br/>δ* = argmin ||δ||0  s.t.  R < 0.20"]:::graphXai
        GROUNDING["Grounding Validator<br/>(E_referenced ⊆ E_subgraph)"]:::graphXai
    end

    %% LAYER 4: SOAR & SAFETY
    subgraph L4 ["4. Policy Remediation & Governance (SOAR)"]
        POL_CHECK["Response Policy Engine<br/>(response_policy.yaml)"]:::soar
        CGROUP_FREEZE["cgroup v2 Freeze Controller<br/>(cgroup.freeze non-destructive)"]:::soar
        NFT_BLOCK["Egress Firewall Isolation<br/>(nftables / iptables drop)"]:::soar
        ROLLBACK["30-Min TTL Rollback Scheduler<br/>(HMAC-SHA256 Audit Receipts)"]:::soar
    end

    %% LAYER 5: INTERACTION & DASHBOARD
    subgraph L5 ["5. Security Operations Center (SOC) Console"]
        FASTAPI["FastAPI REST & WebSocket Gateway<br/>(/v1/events, /v1/incidents, /v1/graph)"]:::uiLayer
        OLLAMA["On-Premises Local LLM<br/>(Ollama @ localhost:11434)"]:::uiLayer
        MITRE_EXP["MITRE ATT&CK Navigator Exporter<br/>(Layer v4.5 JSON)"]:::uiLayer
        TELEMETRY_GAUGE["Live Benchmark Telemetry Bar<br/>(CPU < 2.5%, RAM < 45MB, Latency < 12ms)"]:::uiLayer
        UI_DASH["Interactive Dark-Mode Dashboard<br/>(HTML5 Canvas DAG + Threat Feed)"]:::uiLayer
    end

    %% PIPELINE DATA FLOWS
    L0 -.->|Hardware Trust Context| L2
    BPF_EXEC --> MARKOV
    BPF_VFS --> RULE_ENG
    BPF_SOCK --> RULE_ENG
    PSI_STREAM --> PSI_EWMA
    REPLAY --> MARKOV

    MARKOV --> NOISY_OR
    PSI_EWMA --> NOISY_OR
    RULE_ENG --> NOISY_OR

    NOISY_OR --> PROV_DAG
    NOISY_OR --> CF_SOLVER
    PROV_DAG --> FASTAPI
    CF_SOLVER --> GROUNDING

    GROUNDING --> OLLAMA
    OLLAMA --> FASTAPI

    NOISY_OR --> POL_CHECK
    POL_CHECK --> CGROUP_FREEZE
    POL_CHECK --> NFT_BLOCK
    CGROUP_FREEZE --> ROLLBACK
    NFT_BLOCK --> ROLLBACK
    ROLLBACK --> FASTAPI

    FASTAPI --> UI_DASH
    FASTAPI --> MITRE_EXP
    FASTAPI --> TELEMETRY_GAUGE
```

---

## 🔄 2. Real-Time Streaming Data Flow

```mermaid
sequenceDiagram
    autonumber
    participant K as Linux Kernel (eBPF / PSI)
    participant S as Sensor & Replay Agent
    participant D as AI Detection Engine
    participant G as Provenance Lineage DAG
    participant X as XAI & Grounding Validator
    participant R as Policy Remediation & Rollback
    participant U as Web Dashboard & SOC Analyst

    K->>S: Kernel Event (execve, openat2, connect, PSI pressure)
    S->>D: Ingest Event + Hardware Trust Context
    
    rect rgb(20, 25, 45)
        Note over D: Multi-Signal AI Evaluation
        D->>D: 1. Evaluate Deterministic Rules
        D->>D: 2. Calculate Markov Spawning Surprisal (-log2 P)
        D->>D: 3. Forecast PSI Resource Pressure Velocity
        D->>D: 4. Bayesian Noisy-OR Fusion (Risk Score R)
    end

    D->>G: Ingest Node/Edge & Update Execution DAG
    D->>X: Synthesize L0 Minimal Counterfactual Perturbations
    X->>X: Validate Entity Grounding (E_ref ⊆ E_subgraph)
    
    alt Threat Score R >= 0.90 (Autonomous Containment Allowed)
        D->>R: Execute Non-Destructive cgroup.freeze & Block Egress
        R->>R: Issue HMAC-SHA256 Receipt & Start 30-min Auto-Rollback TTL
    end

    D->>U: Stream Incident, Subgraph, and Live Metrics to UI
    U->>X: Analyst Inquires: "Why was this flagged?"
    X-->>U: Return Verified Natural-Language Counterfactual Explanation
```

---

## 📦 3. Subsystem Component Breakdown

| Layer | Subsystem | File Location | Key Responsibility |
| :--- | :--- | :--- | :--- |
| **0. Trust** | Hardware Attestation | `contracts/` | Validates TPM 2.0 PCR quotes and IMA runtime binary hashes (`TrustContext`). |
| **1. Sensing** | eBPF & Telemetry Sensor | `bpf/`, `agent/` | Captures process executions, file writes, network sockets, and `/proc/pressure` metrics with zero kernel modification. |
| **2. AI Core** | Multi-Signal Risk Engine | `services/detector/app/` | Computes Laplace-smoothed Markov surprisal, EWMA resource pressure forecasting, and Bayesian Noisy-OR fusion. |
| **3. XAI** | Causal DAG & Counterfactuals | `services/graph/`, `counterfactual.py` | Solves $L_0$-minimal feature perturbation and constructs provenance Directed Acyclic Graphs. |
| **4. SOAR** | Policy Engine & Rollback | `services/responder/app/` | Manages `cgroup.freeze`, `nftables` isolation, and 30-minute auto-rollback with HMAC-SHA256 audit receipts. |
| **5. Assistant** | Grounded SOC Interface | `services/api/app/`, `ui/` | Provides local on-premises LLM chat with mechanical grounding validation, live DAG visualizer, and MITRE export. |

---

## 🖼️ How to Export PNG/JPG for Hackathon Upload (Max 300KB)

1. Open **[mermaid.live](https://mermaid.live)** in your browser.
2. Copy and paste the Mermaid code from **Section 1** into the editor.
3. Click **Download PNG** or **Download JPEG** in the bottom-right corner.
4. The generated image will be crisp, professional, perfectly color-coded, and well under the **300KB** portal limit.
