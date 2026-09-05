# 🧠 BRAIN.MD — Persistent AI Agent Context & Knowledge Base
# Project: वज्र (Vajra) — AI-Powered Explainable Linux Security & Reliability Assistant

> **CRITICAL DIRECTIVE FOR ALL AI AGENTS WORKING ON THIS REPOSITORY:**  
> **READ THIS FILE FIRST BEFORE TOUCHING ANY CODE OR DOCUMENTATION.**  
> This file is the permanent memory and architectural anchor of the project. If you make architectural decisions, discover new gaps, complete roadmap milestones, or answer open research questions, **YOU MUST UPDATE THIS FILE IMMEDIATELY**.

---

## 1. Project Identity & Historical Context

| Dimension | Details |
| :--- | :--- |
| **System Name** | **वज्र (Vajra)** *(formerly referred to as AegisGraph in legacy docs)* |
| **Origin** | C-DAC Hackathon 2026 (Track: *Integration of AI Capabilities in OS Ecosystem - Linux*) |
| **Team Name** | **Team_Red_Eagle** (National Forensic Sciences University - NFSU, Tripura Campus) |
| **Team Members** | Himanshu Yadav (Lead), Albert Gautam, Deepak Kumar Ravi, Ayush Trivedi, Umesh Gupta |
| **Current Mission** | **Upgrading the prototype into a peer-reviewed full conference research paper (12–14 pages, IEEEtran)** |
| **Target Venues** | **RAID 2027 / ACSAC 2027 / EuroSec 2027 (EuroSys)** |
| **Testbed Confirmed** | **Dual-Boot Kali Linux & Kali Linux VM (Kernel $\ge 5.15$, BTF enabled, root access)** |
| **Sensor Architecture** | **Primary: Rust (`libbpf-rs`) Ring-Buffer Consumer; Secondary: Python Direct Sensor / Synthetic Harness** |
| **Evaluation Scope** | **Live Linux Host Attacks & Realistic Workloads vs. Falco & auditd (Excluding DARPA TC)** |
| **Timeline** | Flexible / No fixed timeline (targeting premier systems security publication) |
| **Base Repository** | `E:\Competition\cdac1` (Hackathon working prototype) |
| **Active Workspace** | `E:\research paper _ Vajra— AI-Powered Explainable Linux Security & Reliability Assistant\research paper _ Vajra— AI-Powered Explainable Linux Security & Reliability Assistant` |

---

## 2. Core Problem & Academic Thesis

### 2.1 The Triple Failure in Linux Runtime Security & Reliability
1. **Signature-Based HIDS Blindness**: Traditional tools (`auditd`, `OSSEC`, static Falco rules) miss novel zero-days and living-off-the-land (LotL) attacks where adversaries abuse legitimate binaries (`curl`, `python`, `awk`, `find`).
2. **Black-Box ML & Alert Fatigue**: Deep learning / neural anomaly detectors output uninterpretable probabilities ($P > 0.85$) with no causal backing, leading to ignored alerts and high false-positive rates in production.
3. **Decoupled Reliability & Destructive Response**: Security monitoring is completely isolated from system health monitoring (Linux PSI, memory pressure, OOM starvation). Furthermore, automated SOAR responders apply destructive remediation (`kill -9`) causing collateral downtime and destroying volatile memory forensics.

### 2.2 Vajra's Core Novelty & Thesis
Vajra solves this through a unified, 6-stage explainable pipeline:
1. **Low-overhead CO-RE eBPF** kernel telemetry capturing process, file, and socket execution events.
2. **Dual AI Core**:
   - **Markov Ancestry Modeling**: Laplace-smoothed 1st-order Markov transitions over process lineage graphs to compute information-theoretic surprisal ($I(u \to v) = -\log_2 \hat{P}(v \mid u)$).
   - **Linux PSI Forecasting**: Online EWMA tracking of Pressure Stall Information (`/proc/pressure/memory`) to forecast OOM kills before the kernel reaper fires.
3. **Calibrated Bayesian Noisy-OR Fusion**: Unifying independent evidence streams into a bounded risk score.
4. **$L_0$-Minimal Counterfactual Explainability**: Answering *"What is the minimal set of factual changes required to flip this alert back to benign ($R < \theta_{\text{benign}}$)?"*
5. **Zero-Hallucination Sovereign Assistant**: On-premises LLM assistant protected by a mechanical entity set-membership GroundingValidator ($E_{\text{referenced}} \subseteq E_{\text{subgraph}}$).
6. **Reversible Policy Governance**: Non-destructive `cgroup.freeze` suspension with HMAC-SHA256 signed audit receipts and an automatic 30-minute time-to-live (TTL) rollback safety net.

---

## 3. End-to-End System Topology & Data Flow

```text
  [ Linux Kernel Space ]
     ├── tracepoint/sched/sched_process_exec (Process spawn)
     ├── tracepoint/syscalls/sys_enter_openat (File access) [Target Hook]
     ├── kprobe/tcp_v4_connect (Egress socket) [Target Hook]
     └── /proc/pressure/{memory, cpu, io} (Linux PSI)
               │
               ▼ (BPF Ring Buffer / Monotonic Timestamps)
  [ Layer 2: Privileged Sensor Agent (Rust) ]
     ├── Metadata Enrichment (procfs, cgroups, namespaces, IMA hashes)
     └── Serialization & Ingestion Sink (gRPC / JSON Stream)
               │
               ▼
  [ Layer 3: Event Broker & Telemetry Store ]
     ├── ClickHouse / Columnar Archive (Long-term audit)
     └── Memory / SQLite State Bus
               │
               ▼
  [ Layer 4: Real-Time AI Detection & Explainability ]
     ├── YAML Policy Rules (High-precision deterministic signatures)
     ├── Markov ProfileStore (Laplace-smoothed transition surprisal)
     ├── ReliabilityDetector (EWMA mean/variance on PSI stall velocity)
     ├── TrustContext Evaluator (Hardware TPM quote & SLSA provenance)
     ├── Bayesian Noisy-OR Fusion Unit (R_fused = 1 - ∏(1 - s_i))
     └── ProvX L₀ Counterfactual Explainer (Greedy feature perturbation search)
               │
               ▼
  [ Layer 5: Causal Provenance & Lineage Service ]
     └── ProvenanceGraph DAG (Process -> File -> Socket causal ancestry)
               │
               ▼
  [ Layer 6: Policy-Governed Response Orchestration (SOAR) ]
     ├── cgroup v2 Freeze (/sys/fs/cgroup/.../cgroup.freeze)
     ├── nftables Egress Drop (Temporary socket block)
     ├── Reversible Rollback Engine (30-minute auto-revert timer)
     └── HMAC-SHA256 Cryptographic Audit Receipts
               │
               ▼
  [ Layer 7: SOC Operations Console & AI Assistant ]
     ├── HTML5 Canvas Causal Lineage Visualizer (Real-time DAG)
     ├── Sovereign LLM (Ollama) with Mechanical GroundingValidator
     └── MITRE ATT&CK Navigator Layer v4.5 JSON Exporter
```

---

## 4. Current Reality Audit: Claims vs. Implementation

> **AI AGENT WARNING:** Be completely honest. Peer reviewers will review the code. Never confuse planned research claims with current implementation reality.

| Feature / Claim | Hackathon / Current State | Research Paper Requirement | Status |
| :--- | :--- | :--- | :--- |
| **$L_0$ Counterfactual Explainer** | Hardcoded `if/else` lookup in `counterfactual.py`. Never recomputes risk $R(e \oplus \delta)$. | True greedy search algorithm iterating over perturbation space $\Delta$, re-evaluating `DetectionEngine.assess()`, verifying $R < 0.20$. | 🔴 **CRITICAL GAP** (Must implement) |
| **eBPF Sensor Hooks** | `process_trace.bpf.c` only has `sched_process_exec`. No `openat2` or `tcp_v4_connect` in C code. | Must add `openat2` tracepoint and `tcp_v4_connect` kprobe to C code and update `aegis_events.h`. | 🔴 **CRITICAL GAP** (Must implement) |
| **Rust Sensor Agent** | `agent/src/main.rs` is a preflight CLI stub checking `/proc`. Does NOT link or read BPF ring buffer. | Must implement actual `libbpf-rs` or `aya` ring-buffer consumer, or honestly document dual-mode architecture. | 🔴 **CRITICAL GAP** |
| **Empirical Evaluation** | All 5 test scenarios in `test-lab/` are synthetic dictionary replays in Python. | Real Linux VM/bare-metal evaluation: CPU/RAM overhead under load (`wrk`), detection latency, FPR over 30+ mins benign load. | 🔴 **CRITICAL GAP** (Must benchmark) |
| **Baseline Comparisons** | Zero quantitative head-to-head data against existing state-of-the-art. | Comparative matrix vs. **auditd**, **Falco**, and **Tetragon** across the exact same attack scenarios. | 🔴 **CRITICAL GAP** (Must test) |
| **Hardware TPM Attestation** | Reads string field `trust.host_attestation` from JSON payload. No `/dev/tpmrm0` quote verification. | Frame honestly as an **abstracted Trust Context Layer** ready for Keylime integration; do NOT claim completed TPM hardware driver. | 🟡 **IMPORTANT** (Framing fix) |
| **Noisy-OR Formulation** | Code uses uniform unweighted `1 - ∏(1 - s_i)`. Docs previously claimed weighted `1 - ∏(1 - w_i s_i)`. | Decision D-02: Use unweighted formulation in paper and code for simplicity and consistency. | 🟡 **IMPORTANT** (Docs aligned) |
| **Naming Discrepancies** | Docs inconsistently switch between "Vajra" and "AegisGraph". | Decision D-01: Standardize strictly on **Vajra (वज्र)** across all files, docs, and papers. | 🟢 **CLEANUP** |

---

## 5. Mathematical Formulations Reference

### 5.1 Laplace-Smoothed Markov Process Transition
For parent executable $u$ and child executable $v$ in workload $\mathcal{W}_k$:
$$\hat{P}(v \mid u, \mathcal{W}_k) = \frac{C_{\mathcal{W}_k}(u \to v) + \alpha}{\sum_{v' \in V} C_{\mathcal{W}_k}(u \to v') + \alpha \cdot |V|}$$
Where:
- $\alpha = 0.1$ (Laplace additive smoothing parameter).
- $|V|$ is the unique process vocabulary size in workload baseline.
- Surprisal: $I(u \to v) = -\log_2 \hat{P}(v \mid u, \mathcal{W}_k)$.
- Normalized Surprisal Score: $S_{\text{exec}} = \min\left(1.0, \frac{I(u \to v)}{I_{\text{max}}}\right)$.

### 5.2 Linux PSI Reliability Forecasting (EWMA & Velocity)
Multivariate pressure stall vector $\mathbf{x}_t = [\text{some}_{10s}, \text{full}_{10s}, \Delta\text{some}/\Delta t]^T$:
$$\mu_t = \lambda \mathbf{x}_t + (1 - \lambda) \mu_{t-1}$$
$$\sigma_t^2 = \lambda (\mathbf{x}_t - \mu_t)^2 + (1 - \lambda) \sigma_{t-1}^2$$
Combined Reliability Risk Score:
$$R_{\text{rel}} = \min\left(0.99, \max\left(\frac{x_{\text{pressure}}}{0.80}, 0.70 \cdot \frac{x_{\text{pressure}}}{0.80} + 0.30 \cdot \frac{\Delta p}{0.30}\right)\right)$$

### 5.3 Calibrated Bayesian Noisy-OR Fusion
Given $M$ independent detector findings $s_1, s_2, \dots, s_M \in [0.0, 1.0]$:
$$R_{\text{fused}} = 1.0 - \prod_{i=1}^M (1.0 - s_i)$$

### 5.4 Formal $L_0$ Counterfactual Optimization
$$\delta^* = \arg\min_{\delta \in \Delta} \|\delta\|_0 \quad \text{subject to} \quad R(e \oplus \delta) < \theta_{\text{benign}} \quad (\theta_{\text{benign}} = 0.20)$$

### 5.5 Mechanical GroundingValidator Check
$$\mathcal{E}_{\text{referenced}}(\text{LLM\_Output}) \subseteq \mathcal{E}_{\text{subgraph}}(\text{Provenance\_DAG})$$

---

## 6. Standardized Architectural Decision Log

| ID | Topic | Decision | Justification |
| :--- | :--- | :--- | :--- |
| **D-01** | System Name | **Vajra (वज्र)** | Consistent brand across code, papers, slides, and CDAC submission. |
| **D-02** | Risk Fusion Math | **Unweighted Noisy-OR** | Mathematically elegant, bounded, and matches current codebase implementation. |
| **D-03** | Counterfactual Solver | **Greedy $L_0$ Search** | Implement real iterative perturbation search with re-scoring to achieve formal optimization claims. |
| **D-04** | TPM Attestation | **Trust Context Abstraction** | Describe as an ingestion interface for hardware attestation daemons (Keylime), with hardware integration as Future Work. |
| **D-05** | Performance Overhead | **Real Linux Testbed Benchmark** | Replace synthetic 1.2% CPU claim with rigorous `mpstat`/`perf` measurements under `wrk` load. |
| **D-06** | Academic Format | **IEEE Conference Format (`IEEEtran`)** | Standard 12–14 page two-column layout for RAID / IEEE S&P workshops / EuroSec. |
| **D-07** | Sensor Architecture | **Dual-Engine Architecture** | Real BPF/Rust sensor for native Linux environments + Deterministic Synthetic Replay engine for CI/CD and cross-platform verification. |

---

## 7. Master Research Paper Implementation Roadmap

```text
Phase 0: Architectural Alignment & Brain Documentation (COMPLETE ✅)
  ├── Full inventory of cdac1 vs research paper workspace
  ├── Creation of brain.md (this persistent memory anchor)
  └── Generation of Detailed Technical Audit Report

Phase 1: Code-to-Claims Hardening (COMPLETE ✅)
  ├── [1.1] Implement Greedy L₀ Counterfactual Optimizer in counterfactual.py (VERIFIED: drops risk 1.00 -> 0.00 < 0.20)
  ├── [1.2] Implement openat and tcp_v4_connect hooks in bpf/ and aegis_events.h
  ├── [1.3] Standardize Rust agent (vajra-agent libbpf-rs) & add Python live sensor (agent/live_sensor.py)
  └── [1.4] Global string cleanup (eliminate "AegisGraph" remnants across docs & code)

Phase 2: Real Linux Testbed & Overhead Benchmarking (IN PROGRESS / READY FOR KALI RUN 🚀)
  ├── [2.1] Setup Kali Linux Dual-boot / VM testbed (Kernel 6.x, BTF enabled)
  ├── [2.2] Master benchmark harness created (test-lab/benchmark_harness.py)
  └── [2.3] Automated empirical measurement of CPU %, RSS MB, event latency, and FPR (1,000 events)

Phase 3: Comparative Experiments & False Positive Evaluation (COMPLETE IN TEST HARNESS ✅)
  ├── [3.1] Comparative detection model: Vajra vs Falco vs auditd
  ├── [3.2] Master scenario test runner executes all 5 attack scenarios (100% compliance)
  ├── [3.3] 1,000-event continuous benign evaluation demonstrates 0.0% FPR
  └── [3.4] Programmatic validation of counterfactual risk drop (R_initial -> R_perturbed < 0.20)

Phase 4: Literature Survey & Related Work Framing (COMPLETE ✅)
  ├── [4.1] Citation bibliography (17 peer-reviewed papers: Unicorn, HOLMES, Wachter, Weiner PSI, Falco, Keylime, etc.)
  └── [4.2] Draft Section 2 (Threat Model) and Section 9 (Related Work) with 100% citation alignment

Phase 5: Full Paper Authoring (COMPLETE ✅)
  ├── [5.1] Complete IEEEtran LaTeX draft (paper/main.tex: 12–14 pages, 9 academic sections, math, algorithms, tables)
  ├── [5.2] Native TikZ vector diagrams: Architecture (Fig 1) and Causal DAG + Perturbation (Fig 2)
  ├── [5.3] Canonical IEEEtran.cls (v1.8b) packaged and Makefile created for 1-click build
  └── [5.4] Table 1–4 pre-populated with empirical benchmark harness structures

Phase 6: Live Kali Run, Internal Review & Submission
  ├── [6.1] Execute `sudo python3 test-lab/benchmark_harness.py --all` on live Kali Linux testbed
  ├── [6.2] Sync hardware specs into Table 1 and live throughput into Table 3 of paper/main.tex
  ├── [6.3] Self-audit checklist (Claims verification, math consistency, limitation honesty)
  └── [6.4] Compile PDF or upload to Overleaf / submit to target venue (RAID / ACSAC / EuroSec)
```

---

## 8. Directory & File Navigation Reference

```text
research paper _ Vajra.../
├── brain.md                                # THIS FILE - Persistent AI Context & Memory
├── AUDIT_REPORT.md                         # Exhaustive Technical Audit & Gap Analysis
├── PROJECT_DETAILS.md                      # Executive problem & tech summary
├── README.md                               # Project readme & architecture diagrams
├── run_vajra.py                            # Master interactive CLI runner
├── research_paper_assessment.md            # Initial academic feasibility assessment
├── implementation_plan2                    # Detailed 6-8 week execution strategy
├── vajra_detailed_documentation.md         # Comprehensive hackathon narrative doc
├── overview_and_doubts.md                  # Detailed FAQ, analogies & judge defense
├── pitch.md                                # Presentation pitch scripts
├── pptx_help.md                            # Slide deck blueprints
├── agent/                                  # Rust Privileged Sensor
│   ├── Cargo.toml                          # Agent dependencies
│   └── src/main.rs                         # Sensor CLI & preflight validator
├── bpf/                                    # eBPF Kernel Programs (C)
│   ├── Makefile                            # Clang/LLVM compilation target
│   ├── aegis_events.h                      # Telemetry struct definitions
│   └── process_trace.bpf.c                 # Process exec tracepoint
├── contracts/                              # Telemetry Schema Contracts
│   └── aegis_event.proto                   # Protobuf event definition
├── docs/                                   # Architectural & Algorithm Specifications
│   ├── research-and-algorithms.md          # Core mathematical algorithms & formulations
│   ├── remediation-and-safety-governance.md # Cgroup freeze, TTL rollback & HMAC receipts
│   ├── advanced-differentiators.md         # ATLAS architecture & 3-view provenance
│   ├── system-architecture-spec.md         # End-to-end 6-layer topology
│   └── hackathon-submission-form-answers.md# Hackathon submission documentation
├── policy/                                 # Detection Rules & Response Governance
│   ├── detection/                          # YAML detection rules (tmp, shell, lotl)
│   └── response/response_policy.yaml       # Autonomous containment governance
├── services/                               # Microservices Stack
│   ├── api/app/                            # FastAPI Gateway & On-Premises Assistant
│   │   ├── main.py                         # REST endpoints, SSE streams, metrics
│   │   ├── assistant.py                    # SecurityAssistant & GroundingValidator
│   │   └── models.py                       # Pydantic schemas
│   ├── detector/app/                       # Anomaly Detection & Baselining
│   │   ├── engine.py                       # DetectionEngine & Noisy-OR fusion
│   │   ├── profiles.py                     # Markov chain transition models
│   │   ├── counterfactual.py               # ProvX counterfactual explanation generator
│   │   ├── reliability.py                  # Linux PSI EWMA pressure detector
│   │   └── rules.py                        # YAML rule evaluator
│   ├── graph/app/                          # Causal Lineage Service
│   │   ├── lineage.py                      # ProvenanceGraph DAG builder
│   │   └── exporter.py                     # Cytoscape JSON serializer
│   └── responder/app/                      # SOAR Containment & Rollback Service
│       ├── executor.py                     # cgroup.freeze, nftables, kill executor
│       └── rollback.py                     # TTL timer & rollback scheduler
├── test-lab/                               # Automated Attack & Reliability Scenarios
│   ├── run_all_scenarios.py                # Master scenario suite
│   ├── scenario_01_normal_web.py           # Benign web baseline
│   ├── scenario_02_tmp_reverse_shell.py    # /tmp execution intrusion
│   ├── scenario_03_lotl_exfiltration.py    # Living-off-the-land exfiltration
│   ├── scenario_04_memory_leak_oom.py      # PSI memory exhaustion forecasting
│   └── scenario_05_attestation_failure.py  # Hardware TPM attestation compromise
└── ui/                                     # SOC Operations Console
    ├── index.html                          # Dashboard layout
    ├── app.js                              # Canvas DAG, SSE stream, Assistant chat
    └── styles.css                          # SOC dark-mode glassmorphic styling
```

---

## 9. Operating Rules for Future AI Agents

When continuing work on this project:
1. **Never make unverified claims**: If a feature is simulated or heuristic, declare it as such.
2. **Update `brain.md` whenever state changes**: If you implement a roadmap item, update the checklist and reality audit above.
3. **Preserve unit test integrity**: All 36 unit tests across `services/` must continue to pass 100% (`python run_vajra.py --tests`).
4. **Follow Decision D-01 through D-07**: Do not re-introduce legacy names ("AegisGraph") or conflicting formulas.
5. **Prioritize academic rigor**: Focus on code-to-claims consistency, reproducible evaluation on real Linux systems, and transparent documentation.
