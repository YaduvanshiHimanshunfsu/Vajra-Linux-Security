#System Architecture & End-to-End Technical Specification

This document provides the architectural specification for the Vajra (वज्र) platform, connecting Linux kernel telemetry, streaming anomaly detection, explainable AI reasoning, automated policy response, and the operator assistant UI.

---

## 1. System Topology & Data Flow

```mermaid
flowchart TD
    subgraph Kernel_Layer ["Layer 1: Linux Kernel Telemetry & Ingestion"]
        EBPF_EXEC["tracepoint/sched/sched_process_exec"]
        EBPF_EXIT["tracepoint/sched/sched_process_exit"]
        EBPF_NET["kprobe/sys_enter_connect & accept"]
        EBPF_FILE["kprobe/sys_enter_openat2 & lsm/file_open"]
        LINUX_PSI["/proc/pressure/memory & cpu"]
        SIM_REPLAY["Synthetic Event & Scenario Replay Engine"]
    end

    subgraph Sensor_Agent ["Layer 2: Privileged Sensor Agent (Rust)"]
        RING_BUF["BPF Ring Buffer Consumer"]
        ENRICH["Metadata Enrichment (PID -> cgroup, container_id, user, IMA hash)"]
        SINK["Secure Event Transmitter (gRPC / Redpanda Kafka Producer)"]
    end

    subgraph Storage_Bus ["Layer 3: Event Bus & Storage Tier"]
        REDPANDA["Redpanda / Kafka (Topic: aegis.events.v1)"]
        CLICKHOUSE["ClickHouse Columnar Database (Telemetry Archive)"]
        SQLITE_DB["Fast-Access State DB / SQLite & Profile Registry"]
    end

    subgraph Analytics_Engine ["Layer 4: Real-Time AI Detection & Explainability"]
        DETECTOR["Streaming Detection Engine (FastAPI / Worker)"]
        RULE_ENGINE["High-Precision Policy Rule Engine (YAML)"]
        MARKOV_PROFILE["Workload Behavioral Baselines (Markov Transitions & Entropy)"]
        RELIABILITY_MODELS["PSI & Resource Anomaly Detector (EWMA & Outlier Scoring)"]
        COUNTERFACTUAL_GEN["Counterfactual Explanation Synthesizer"]
        FUSION_UNIT["Calibrated Risk Fusion (Bayesian Noisy-OR)"]
    end

    subgraph Remediation_Layer ["Layer 5: Policy-Governed Response Engine (Responder)"]
        RESP_ORCH["Response Orchestrator (services/responder)"]
        POLICY_VERIFIER["Cryptographic Policy & Scope Verifier"]
        CONTAIN_ACTIONS["Containment Handlers:\n- SIGTERM/SIGKILL Process Group\n- Cgroup V2 Freeze (/sys/fs/cgroup/.../cgroup.freeze)\n- Network Egress Drop (nftables / iptables)\n- Container Isolation"]
        ROLLBACK_CTRL["TTL Expiry & Audit Receipt Controller"]
    end

    subgraph User_Interface ["Layer 6: Security Assistant & Visualizer (UI)"]
        REST_API["Vajra (वज्र) API Gateway (FastAPI)"]
        LIVE_STREAM["WebSocket / Server-Sent Events (SSE)"]
        WEB_UI["Interactive Security Assistant Dashboard:\n- Live Incident Stream\n- Causal Provenance Graph\n- AI Explanation & Chat Assistant\n- 1-Click Containment Console"]
    end

    EBPF_EXEC --> RING_BUF
    EBPF_EXIT --> RING_BUF
    EBPF_NET --> RING_BUF
    EBPF_FILE --> RING_BUF
    LINUX_PSI --> RING_BUF
    SIM_REPLAY --> SINK

    RING_BUF --> ENRICH
    ENRICH --> SINK
    SINK --> REDPANDA

    REDPANDA --> CLICKHOUSE
    REDPANDA --> DETECTOR

    DETECTOR --> RULE_ENGINE
    DETECTOR --> MARKOV_PROFILE
    DETECTOR --> RELIABILITY_MODELS
    DETECTOR --> FUSION_UNIT
    FUSION_UNIT --> COUNTERFACTUAL_GEN
    COUNTERFACTUAL_GEN --> SQLITE_DB
    COUNTERFACTUAL_GEN --> REST_API

    REST_API --> LIVE_STREAM
    LIVE_STREAM --> WEB_UI

    WEB_UI --> REST_API
    REST_API --> RESP_ORCH
    RESP_ORCH --> POLICY_VERIFIER
    POLICY_VERIFIER --> CONTAIN_ACTIONS
    CONTAIN_ACTIONS --> ROLLBACK_CTRL
```

---

## 2. Component Directory Structure

```text
e:/Competition/cdac1/
├── agent/                         # Rust Privileged Sensor
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs                # Sensor CLI & Ringbuffer Reader
│       ├── enricher.rs            # Procfs, cgroup & container metadata enricher
│       └── simulator.rs           # Deterministic cross-platform scenario generator
├── bpf/                           # eBPF C Kernel Programs
│   ├── aegis_events.h             # Common event header
│   ├── process_trace.bpf.c        # Process exec/exit & path extraction
│   └── network_trace.bpf.c        # Connect/accept socket tracking
├── contracts/                     # Unified Data Contracts
│   └── aegis_event.proto          # Protobuf event definition
├── docs/                          # Architecture & Research Records
│   ├── architecture.md
│   ├── advanced-differentiators.md
│   ├── research-and-algorithms.md
│   ├── system-architecture-spec.md
│   └── remediation-and-safety-governance.md
├── policy/                        # Detection Rules & Response Governance
│   ├── detection/
│   │   ├── temporary_execution.yaml
│   │   ├── reverse_shell.yaml
│   │   ├── credential_tampering.yaml
│   │   └── unverified_binary.yaml
│   └── response/
│       └── response_policy.yaml
├── services/                      # Python Core Services
│   ├── api/                       # API Gateway & Assistant Backend
│   │   └── app/
│   │       ├── main.py            # FastAPI endpoints (Assess, Incidents, Assistant Chat, Remediate)
│   │       ├── models.py          # Unified Pydantic models
│   │       └── assistant.py       # Explainable AI Assistant logic (LLM / RAG / Counterfactuals)
│   ├── detector/                  # Anomaly Detection & Baselining
│   │   └── app/
│   │       ├── domain.py          # Domain data classes
│   │       ├── engine.py          # DetectionEngine with Noisy-OR Fusion
│   │       ├── profiles.py        # Markov Transition & Entropy ProfileStore
│   │       ├── rules.py           # YAML Policy Rule Engine
│   │       ├── reliability.py     # PSI & Memory Leak Anomaly Detector
│   │       ├── counterfactual.py  # Counterfactual Explanation Generator
│   │       └── worker.py          # Real-time event consumer
│   ├── graph/                     # Causal Provenance Graph Service
│   │   └── app/
│   │       ├── lineage.py         # Process & File & Network Provenance DAG builder
│   │       └── exporter.py        # Cytoscape / D3 graph JSON serializer
│   └── responder/                 # Automated Containment & Rollback Service
│       └── app/
│           ├── executor.rs / .py  # Process kill, cgroup freeze, iptables drop
│           ├── policy_check.py    # Policy verification & signature validation
│           └── rollback.py        # TTL timer & automatic rollback scheduler
├── test-lab/                      # Automated Attack & Reliability Scenarios
│   ├── scenario_01_normal_web.py
│   ├── scenario_02_tmp_reverse_shell.py
│   ├── scenario_03_lotl_exfiltration.py
│   ├── scenario_04_memory_leak_oom.py
│   └── scenario_05_attestation_failure.py
└── ui/                            # Interactive Web Assistant Dashboard
    ├── index.html                 # Modern glassmorphism dashboard
    ├── app.js                     # Real-time SSE, interactive graph, AI chat & action triggers
    └── styles.css                 # Premium dark-mode security operations center styling
```
