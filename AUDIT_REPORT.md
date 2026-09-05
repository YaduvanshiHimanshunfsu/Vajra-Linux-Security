# 🛡️ VAJRA (वज्र) — Comprehensive Technical Audit & Academic Evolution Report

**Project Title**: वज्र (Vajra) — AI-Powered Explainable Linux Security & Reliability Assistant  
**Origin Project**: `E:\Competition\cdac1` (C-DAC Hackathon 2026 Entry, Team Red Eagle)  
**Research Workspace**: `E:\research paper _ Vajra— AI-Powered Explainable Linux Security & Reliability Assistant\research paper _ Vajra— AI-Powered Explainable Linux Security & Reliability Assistant`  
**Date**: September 2026  
**Auditor**: Antigravity AI Systems Architect & Security Researcher  

---

## Table of Contents
1. [Executive Summary & Historical Context](#1-executive-summary--historical-context)
2. [Comparative Archeology: Competition vs. Research Repository](#2-comparative-archeology-competition-vs-research-repository)
3. [Exhaustive Review of Project Documentation & Markdown Files](#3-exhaustive-review-of-project-documentation--markdown-files)
4. [Deep Technical Codebase Audit & Architectural Reality Check](#4-deep-technical-codebase-audit--architectural-reality-check)
   - [4.1 Kernel Telemetry & Privileged Sensor Layer (`bpf/`, `agent/`)](#41-kernel-telemetry--privileged-sensor-layer-bpf-agent)
   - [4.2 AI Detection Core & Mathematical Rigor (`services/detector/`)](#42-ai-detection-core--mathematical-rigor-servicesdetector)
   - [4.3 Counterfactual Explainability ($L_0$ Solver)](#43-counterfactual-explainability-l0-solver)
   - [4.4 Causal Provenance Graph Engine (`services/graph/`)](#44-causal-provenance-graph-engine-servicesgraph)
   - [4.5 Reversible SOAR Containment & Safety Governance (`services/responder/`)](#45-reversible-soar-containment--safety-governance-servicesresponder)
   - [4.6 Sovereign AI Operations Assistant (`services/api/`)](#46-sovereign-ai-operations-assistant-servicesapi)
   - [4.7 Automated Test Lab & Benchmarking Harness (`test-lab/`, `run_vajra.py`)](#47-automated-test-lab--benchmarking-harness-test-lab-run_vajrapy)
5. [Academic Feasibility & Peer-Review Threat Analysis](#5-academic-feasibility--peer-review-threat-analysis)
6. [Target Venues & Publication Strategy](#6-target-venues--publication-strategy)
7. [Step-by-Step Evolution Roadmap (Phases 0 to 6)](#7-step-by-step-evolution-roadmap-phases-0-to-6)
8. [Critical Inquiries & Open Questions for the Author](#8-critical-inquiries--open-questions-for-the-author)

---

## 1. Executive Summary & Historical Context

The project **वज्र (Vajra)** was conceived and developed by **Team_Red_Eagle** from the National Forensic Sciences University (NFSU), Tripura Campus (Himanshu Yadav, Albert Gautam, Deepak Kumar Ravi, Ayush Trivedi, and Umesh Gupta) for the **C-DAC SSM Hackathon 2026** under the theme *"Integration of AI Capabilities in the OS Ecosystem (Linux Based)"*. 

The team engineered a software prototype addressing three critical failures in modern Linux server security and operations:
1. **Signature-based HIDS (auditd, OSSEC) blindness** to novel exploits and Living-off-the-Land (LotL) abuse of system utilities (`curl`, `awk`, `find`).
2. **Black-box ML alert fatigue**, where opaque anomaly probabilities leave SOC operators unable to determine root causes or explain why an alert fired.
3. **Decoupled reliability monitoring and destructive responses**, where resource pressure (OOM kills, memory leaks) is monitored separately from security, and automated SOAR tools fire destructive `SIGKILL` commands that destroy forensically valuable volatile memory and cause service downtime.

The current initiative is to **elevate this hackathon-winning prototype into a high-impact, peer-reviewed academic research paper**.

### Verdict: Strong Theoretical Foundation, Substantial Empirical Gaps
The core research ideas—unifying **CO-RE eBPF**, **Laplace-smoothed Markov process surprisal**, **online EWMA Linux PSI forecasting**, **$L_0$-minimal counterfactual explainability**, **mechanical entity-grounded LLM reasoning**, and **reversible `cgroup.freeze` containment**—constitute a legitimate and publishable contribution to systems security. However, as it stands, the codebase contains substantial **gaps between documentation claims and actual implementation** that would result in immediate rejection by peer reviewers at top venues (USENIX Security, IEEE S&P, RAID, or EuroSec). This audit details every gap and provides the exact technical path to close them.

---

## 2. Comparative Archeology: Competition vs. Research Repository

A bitwise and structural comparison was performed between the competition source directory `E:\Competition\cdac1` and the research directory `E:\research paper _ Vajra— AI-Powered Explainable Linux Security & Reliability Assistant\research paper _ Vajra— AI-Powered Explainable Linux Security & Reliability Assistant`.

### Findings:
1. **Codebase Inheritance**: The research workspace is a direct clone of `cdac1`. All existing Python services, Rust files, eBPF C programs, test scenarios, policy YAMLs, and web assets are identical in size and content.
2. **New Research Artifacts Added in Workspace**:
   - `research_paper_assessment.md` (9,529 bytes): An initial critical peer-review feasibility assessment identifying key vulnerabilities (synthetic benchmarks, fake L₀ solver, missing eBPF hooks).
   - `implementation_plan_to research paper` (19,549 bytes): An initial 6–8 week rough conversion plan with team assignments.
   - `implementation_plan2` (35,910 bytes): A comprehensive Phase 0–6 document establishing page budgets, decision logs, and an academic bibliography.
3. **Missing from Research Workspace**:
   - `CDAC HACKATHON 2024 Integration of AI capabilities in the OS ecosystem(Linux Based).pdf` (1.83 MB) was retained only in `cdac1`. (Note: PDF inspection reveals the presentation deck title is "CDAC HACKATHON 2026").

---

## 3. Exhaustive Review of Project Documentation & Markdown Files

The project contains over 300 KB of detailed markdown specifications, pitch decks, FAQs, and algorithm docs. Below is an exhaustive synthesis:

### 3.1 `research_paper_assessment.md`
- **Core takeaway**: Identifies the exact "kill-switches" in peer review:
  - *Problem 1*: The $L_0$ solver is a hardcoded lookup table, not an optimizer.
  - *Problem 2*: Zero real-world evaluation on a live Linux kernel; all 5 scenarios are synthetic Python replays.
  - *Problem 3*: Hardware TPM 2.0 PCR attestation is simulated via a JSON string.
  - *Problem 4*: Performance benchmarks (1.2% CPU, 36.4 MB RAM, 4.5 ms latency) were measured on synthetic replays, not under live kernel load.
  - *Problem 5*: Missing Related Work section (lacks positioning against Unicorn, HOLMES, Falco, Tetragon, DiCE, Weiner PSI).
  - *Problem 6*: `process_trace.bpf.c` only implements 1 hook (`sched_process_exec`), whereas docs claim 4 hooks.

### 3.2 `implementation_plan2`
- Documents confirmed status: Author indicates a Linux VM with eBPF (kernel ≥ 5.15) and BTF support is available, and targets a **full 12–14 page IEEE/USENIX conference paper**.
- Establishes standardized decisions:
  - **D-01**: Standardize name to **Vajra (वज्र)** everywhere.
  - **D-02**: Adopt **unweighted Noisy-OR** ($R = 1 - \prod(1 - s_i)$).
  - **D-03**: Implement a **true Greedy $L_0$ search algorithm**.
  - **D-04**: Reframe TPM as an **abstracted Trust Context Layer**.
  - **D-05**: Measure real overhead via `perf stat`, `mpstat`, and `wrk` on Linux.
  - **D-07**: Add missing eBPF hooks (`openat2`, `tcp_v4_connect`).

### 3.3 `overview_and_doubts.md` (51 KB)
- A masterclass in intuitive explanations, analogies, and defense against tough judge questions:
  - Explains why deep neural networks (Transformers/LSTMs) were rejected for kernel telemetry: inference takes 50–200 ms and gigabytes of RAM, whereas Laplace Markov lookup and EWMA take $O(1)$ constant time with 36 MB RAM.
  - Answers judge skepticism regarding eBPF running on Windows: Explains the role of the **Deterministic Synthetic Replay Sensor** for cross-platform portability while maintaining identical math and SOAR logic.
  - Details the 30-minute auto-rollback TTL philosophy: prevents operator absence from permanently freezing critical services on false positives.

### 3.4 `vajra_detailed_documentation.md` (46 KB)
- Lays out the 6-stage operational pipeline:
  1. *Kernel Telemetry (eBPF)*
  2. *Behavioral Normality Modeling (Markov)*
  3. *Proactive Reliability Monitoring (PSI)*
  4. *Counterfactual Explainability (ProvX)*
  5. *Policy-Governed Response (cgroup v2)*
  6. *Grounded AI Operations Assistant*
- Details 4 real-world attack scenarios and contrasts them against traditional EDR/SIEM tools.

### 3.5 `docs/research-and-algorithms.md`
- Provides the formal mathematics:
  - Event tuple definition: $e_i = \langle \tau_i, \mathcal{W}_i, \mathcal{P}_i, \text{type}_i, \mathcal{O}_i, \mathcal{T}_i, \mathcal{A}_i \rangle$.
  - Laplace-smoothed Markov transition probability and surprisal:
    $$\hat{P}(v \mid u, \mathcal{W}_k) = \frac{C_{\mathcal{W}_k}(u \to v) + \alpha}{\sum_{v' \in V} C_{\mathcal{W}_k}(u \to v') + \alpha \cdot |V|}, \quad I(u \to v) = -\log_2 \hat{P}(v \mid u, \mathcal{W}_k)$$
  - Multivariate Linux PSI EWMA equations and Z-score outlier detection.
  - $L_0$ counterfactual minimization formulation:
    $$\delta^* = \arg\min_{\delta \in \Delta} \|\delta\|_0 \quad \text{s.t.} \quad R(e \oplus \delta) < \theta_{\text{benign}}$$

### 3.6 `docs/advanced-differentiators.md` (ATLAS)
- Specifies **ATLAS** (Attested Temporal Lineage and Adaptive Security).
- Mandates a **3-View Temporal Provenance Graph**:
  1. *Execution View*: Process, file, socket, privilege edges.
  2. *Trust View*: Image digest, SBOM, SLSA provenance, IMA hash, TPM quote.
  3. *Service View*: OpenTelemetry trace, systemd unit, cgroup, PSI health.
- Introduces deception as high-confidence evidence (canary credentials in `/etc/shadow` decoys).

### 3.7 `docs/remediation-and-safety-governance.md`
- Details the containment primitives (`cgroup.freeze`, `nftables` egress block, `kill`, container quarantine).
- Enforces cryptographic audit receipts:
  $$\text{Receipt} = \text{HMAC-SHA256}(\text{ActionID} \,\|\, \text{TargetPID} \,\|\, \text{RuleID} \,\|\, \text{Timestamp} \,\|\, \text{OperatorID})$$

---

## 4. Deep Technical Codebase Audit & Architectural Reality Check

A line-by-line inspection of all source code files revealed the following exact technical realities:

### 4.1 Kernel Telemetry & Privileged Sensor Layer (`bpf/`, `agent/`)

#### The eBPF Program (`bpf/process_trace.bpf.c`):
- **Hook Present**: Single tracepoint `SEC("tracepoint/sched/sched_process_exec")`.
- **Extraction Logic**: Uses BPF CO-RE helper `BPF_CORE_READ(task, mm, exe_file)` to extract binary dentry paths from the Linux `task_struct`.
- **Ring Buffer**: Correctly defines a BPF ring buffer map `process_events` with capacity $2^{24}$ (16 MB).
- **CRITICAL GAP**: Tracepoints for `openat2` (`vfs_open`), `tcp_v4_connect` (socket connections), and `sched_process_exit` are **completely absent** from the C code. Furthermore, `aegis_events.h` defines only `AEGIS_PROCESS_EXEC` and `AEGIS_PROCESS_EXIT`.

#### The Rust Agent (`agent/src/main.rs`):
- **Dependencies (`agent/Cargo.toml`)**: Only includes `anyhow`, `clap`, `serde`, `serde_json`, `thiserror`. It does **not** include `libbpf-rs`, `aya`, or any kernel BPF loader library.
- **Implementation Reality**: `main.rs` is currently an environment preflight checker. It verifies if `/sys/kernel/btf/vmlinux` and `/proc/pressure/memory` exist, and if `--simulate` is provided, prints a single hardcoded JSON event to stdout.
- **CRITICAL GAP**: The Rust agent does not attach or read from the kernel BPF ring buffer. The entire pipeline currently runs via the Python scenario scripts or synthetic inputs.

---

### 4.2 AI Detection Core & Mathematical Rigor (`services/detector/`)

#### 1. Markov Behavioral Profiling (`profiles.py`):
- **Implementation Quality**: **High**.
- Implements `WorkloadProfile` using `collections.Counter`.
- Computes Laplace-smoothed probability:
  $$\text{prob} = \frac{\text{count} + 0.1}{\text{parent\_total} + 0.1 \cdot |V|}$$
- Computes surprisal $-\log_2(\text{prob})$ normalized against theoretical maximum surprisal. Correctly applies novelty thresholds ($\ge 0.70$ flags medium/high/critical anomaly).
- Also profiles network destination frequency and sensitive file access paths (`/etc/shadow`, `.env`, `id_rsa`).

#### 2. Linux PSI Reliability Forecasting (`reliability.py`):
- **Implementation Quality**: **High**.
- Correctly maintains online EWMA mean and variance:
  $$\text{diff} = x_t - \mu_{t-1}, \quad \mu_t = \mu_{t-1} + \alpha \cdot \text{diff}, \quad \sigma_t^2 = (1 - \alpha)(\sigma_{t-1}^2 + \alpha \cdot \text{diff}^2)$$
- Combines static pressure magnitude ($\text{ratio} / 0.80$) with instantaneous surge velocity ($\Delta p / 0.30$) to detect impending runaway memory leaks before the kernel OOM killer triggers.

#### 3. Bayesian Risk Fusion & Baseline Governance (`engine.py`):
- **Implementation Quality**: **Clean and robust**.
- Fuses evidence via Noisy-OR:
  $$R_{\text{fused}} = 1.0 - \prod (1.0 - s_i)$$
- Enforces strict **anti-poisoning baseline gating**: An incoming event is learned into the profile **only** if:
  1. `attributes["baseline_eligible"] == "true"`
  2. $R_{\text{security}} < 0.25$
  3. $R_{\text{reliability}} < 0.25$
  4. $\text{telemetry\_trust} \ge 0.95$
- Gating autonomous containment: Containment is locked if hardware attestation drops below 0.90.

---

### 4.3 Counterfactual Explainability ($L_0$ Solver)

#### Current Implementation (`counterfactual.py`):
- **The Problem**: Claims to solve:
  $$\delta^* = \arg\min_{\delta \in \Delta} \|\delta\|_0 \quad \text{s.t.} \quad R(e \oplus \delta) < \theta_{\text{benign}}$$
- **The Reality**: The current code contains hardcoded `if/else` checks:
  ```python
  if event.trust.artifact_verification == "failed":
      deltas.append(CounterfactualDelta("trust.artifact_verification", "failed", "verified", -0.45))
  if event.object_value.startswith(("/tmp/", "/dev/shm/")):
      deltas.append(CounterfactualDelta("subject.executable", event.object_value, "/usr/bin/approved_binary", -0.40))
  ```
  It **never re-evaluates** the detection engine, never checks if $R(e \oplus \delta) < 0.20$, and does not minimize $\|\delta\|_0$.
- **Academic Consequence**: Reviewers will immediately dismiss this as claiming a formal mathematical optimization while implementing a static heuristic template.

---

### 4.4 Causal Provenance Graph Engine (`services/graph/`)

#### Graph Construction (`lineage.py`):
- Implements `ProvenanceGraph` tracking `GraphNode` (`process`, `file`, `socket`) and `GraphEdge` (`SPAWNED`, `EXECUTED`, `CONNECTED_TO`, `ACCESSED`).
- Enforces maximum node and edge bounds (500 nodes, 2000 edges) to prevent memory exhaustion.
- Implements `extract_causal_path(target_node_id)` using reverse adjacency traversal to reconstruct ancestral root-cause trees.
- Serializes graphs to Cytoscape JSON format (`exporter.py`) for frontend rendering.

---

### 4.5 Reversible SOAR Containment & Safety Governance (`services/responder/`)

#### Containment Handlers (`executor.py`):
- **`freeze_cgroup`**: Attempts to write `"1"` to `/sys/fs/cgroup/{cgroup}/cgroup.freeze`. On non-Linux hosts or unprivileged runs, gracefully falls back to simulation mode with logged warning.
- **`block_egress`**: Generates a simulated/real firewall rule for target destination IP/ports.
- **`terminate_process`**: Issues `os.kill(pid, SIGTERM)` with fallback to `SIGKILL`.
- **HMAC Receipts**: Signs every action using `hmac.new(secret_key, msg, hashlib.sha256)`.
- **Rollback Engine (`rollback.py`)**: Schedules 30-minute timers to automatically unfreeze cgroups and delete firewall drop rules unless explicitly confirmed by a human analyst.

---

### 4.6 Sovereign AI Operations Assistant (`services/api/`)

#### Mechanical GroundingValidator (`assistant.py`):
- Extracts all process paths, IPs, and PIDs from generated LLM text via regex.
- Enforces strict set-membership:
  $$\mathcal{E}_{\text{referenced}} \subseteq \mathcal{E}_{\text{subgraph}}$$
- If the LLM invents or hallucinates any entity not present in the verified kernel graph, the output is rejected and replaced with a deterministic mathematical report.
- Integrates with local Ollama (`llama3`) with a 2-second timeout, falling back seamlessly to deterministic rules.

---

### 4.7 Automated Test Lab & Benchmarking Harness (`test-lab/`, `run_vajra.py`)

- **Scenario 1**: Normal Web Workload (`systemd` $\to$ `nginx` master $\to$ worker) $\implies R_{\text{sec}} \le 0.20$, baseline updated.
- **Scenario 2**: `/tmp` Reverse Shell (`nginx` $\to$ `/tmp/kworker_rev` $\to$ external IP) $\implies R_{\text{sec}} \ge 0.90$.
- **Scenario 3**: Living-off-the-Land (`curl` reading decoy `/etc/shadow`) $\implies R_{\text{sec}} \ge 0.90$.
- **Scenario 4**: PSI Memory Spike ($\text{pressure} \ge 0.85$, surge $\ge 0.30$) $\implies R_{\text{rel}} \ge 0.80$.
- **Scenario 5**: Hardware TPM Attestation Compromise (`host_attestation = "failed"`) $\implies \text{trust} = 0.00$, baseline frozen, automation locked.
- **Unit Tests**: All 36 unit tests pass across detector, api, graph, and responder.

---

## 5. Academic Feasibility & Peer-Review Threat Analysis

| Evaluation Criterion | Current Hackathon State | Reviewer Reaction | Required Research Paper Action |
| :--- | :--- | :--- | :--- |
| **System Novelty** | High (Markov + PSI + $L_0$ XAI + Reversible SOAR) | "Interesting and cohesive architectural vision." | Highlight unified design in Section 3. |
| **Algorithm Soundness** | Partial (Markov & PSI math is real; $L_0$ is fake) | **REJECT**: "Claims formal optimization but implements if-else lookup." | Implement real greedy $L_0$ search with re-scoring. |
| **Kernel Implementation** | Incomplete (1 hook in BPF; Rust agent is a CLI stub) | **REJECT**: "System claims eBPF runtime but is tested purely via synthetic Python dictionaries." | Add `openat2` + `tcp_v4_connect` to BPF; implement BPF ring reader in Rust or Python `bcc`/`libbpf`. |
| **Evaluation Rigor** | Zero real-world benchmarking (synthetic numbers) | **DESK REJECT**: "No empirical measurements on live systems; no baseline comparisons." | Benchmark on Ubuntu VM under `wrk` load; compare head-to-head against Falco & auditd. |
| **False Positive Rate** | Unmeasured on long-running workloads | **REJECT**: "Cannot assess utility without FPR over benign workloads." | Run 30+ minute benign workload (nginx + curl loop) and compute $\text{FPR} = \frac{\text{FP}}{\text{FP} + \text{TN}}$. |
| **Hardware Attestation** | Reads string field from JSON | "Misleading claim of hardware TPM attestation." | Reframe as "Trust Context Abstraction Layer" with Keylime cited as future driver integration. |

---

## 6. Target Venues & Publication Strategy

### Recommended Venue Tiering:

```
                  ┌──────────────────────────────────────────────┐
                  │              arXiv cs.CR Preprint            │
                  │   (Immediate timestamp & community visibility│
                  └──────────────────────┬───────────────────────┘
                                         │
                 ┌───────────────────────┴───────────────────────┐
                 ▼                                               ▼
  ┌──────────────────────────────┐                ┌──────────────────────────────┐
  │     RAID 2027 (Full Paper)   │                │   EuroSec 2027 (EuroSys WS)  │
  │  - 12-16 pages IEEE format   │                │   - 6-8 pages short paper    │
  │  - Primary Systems IDS venue │                │   - Systems prototype focus  │
  │  - Full evaluation required  │                │   - Shorter review cycle     │
  └──────────────────────────────┘                └──────────────────────────────┘
```

1. **RAID (International Symposium on Research in Attacks, Intrusions, and Defenses)**:
   - *Fit*: **Premier Target**. RAID is the premier academic venue for practical, runtime intrusion detection systems, eBPF telemetry, and novel host anomaly detection.
2. **EuroSec (European Workshop on Systems Security - co-located with EuroSys)**:
   - *Fit*: **Ideal Alternative / Short Paper Track**. Focuses on systems security prototypes, OS extensions, and eBPF mechanisms.
3. **USENIX CSET (Cybersecurity Experimentation and Test)**:
   - *Fit*: Strong fit if highlighting the synthetic vs. real testbed methodology and reproducibility.
4. **IEEE S&P / USENIX Security Workshops (e.g., SaTML or Safe AI)**:
   - *Fit*: Excellent venue if spinning off the **GroundingValidator** as a focused contribution on eliminating hallucinations in security LLMs.

---

## 7. Step-by-Step Evolution Roadmap (Phases 0 to 6)

### Phase 0: Foundations & Context Anchor *(Completed ✅)*
- [x] Full audit of `cdac1` and research paper workspace.
- [x] Creation of `brain.md` persistent knowledge base.
- [x] Creation of `AUDIT_REPORT.md` detailed technical analysis.

### Phase 1: Code-to-Claims Alignment (Weeks 1–2)
1. **Implement True Greedy $L_0$ Counterfactual Optimizer (`counterfactual.py`)**:
   - Define bounded perturbation space $\Delta = \{\text{path}, \text{artifact\_verification}, \text{host\_attestation}, \text{parent}, \text{pressure}\}$.
   - Algorithm:
     ```python
     def find_minimal_counterfactual(event, engine, theta_benign=0.20):
         deltas = []
         current_event = copy(event)
         for feature, target_val in candidate_perturbations(event):
             perturbed = apply_perturbation(current_event, feature, target_val)
             new_assessment = engine.assess(perturbed)
             deltas.append(CounterfactualDelta(feature, event_val, target_val, score_drop))
             current_event = perturbed
             if new_assessment.security_score < theta_benign:
                 return deltas, new_assessment.security_score
     ```
2. **Extend eBPF C Hooks (`bpf/process_trace.bpf.c`)**:
   - Add `tracepoint/syscalls/sys_enter_openat` for file access tracking.
   - Add `kprobe/tcp_v4_connect` for outbound socket IP/port tracking.
   - Update `aegis_events.h` with `aegis_file_event` and `aegis_net_event` structs.
3. **Bridge Privileged Telemetry (Sensor)**:
   - Either complete Rust agent ring-buffer reader using `libbpf-rs` or implement a lightweight Python `bcc`/`libbpf` loader so events flow directly from kernel to detection engine.
4. **Global String & Formatting Cleanup**:
   - Remove all occurrences of "AegisGraph" across `docs/` and standardize on **Vajra (वज्र)**.
   - Align Noisy-OR documentation with unweighted engine code.

### Phase 2: Live Linux Testbed & Overhead Measurement (Weeks 2–3)
1. Configure Ubuntu 22.04 LTS VM (Kernel 6.x, BTF enabled).
2. Attach eBPF probes via `bpftool prog load` and verify kernel events fire on real system activity (`ls`, `cat /etc/shadow`).
3. Benchmark overhead under realistic workload:
   - Run Nginx with `wrk -t4 -c100 -d60s http://localhost/`.
   - Measure CPU cycles (`perf stat`), CPU % (`mpstat 1 60`), and VmRSS (`/proc/{pid}/status`).
   - Measure end-to-end event latency from kernel timestamp to assessment completion.

### Phase 3: Comparative Experiments & False Positive Evaluation (Weeks 3–4)
1. Install **Falco** and **auditd** on the same VM.
2. Configure auditd rules and Falco rules matching Vajra's scope.
3. Run scenarios 1 through 5 across all three systems and record True Positive (TP), False Negative (FN), and alert latency.
4. Execute a 30-minute continuous benign workload script and record False Positive Rate ($\text{FPR} = \text{FP} / (\text{FP} + \text{TN})$).

### Phase 4: Literature Review & Academic Framing (Weeks 4–5)
1. Survey and cite 16+ core academic papers (Unicorn, HOLMES, Wachter XAI, Weiner PSI, Warrender syscall anomaly, Rawte LLM hallucination).
2. Draft Section 2 (*Threat Model*) and Section 8 (*Related Work*).

### Phase 5: Full Paper Drafting (Weeks 5–7)
1. Write 12–14 page IEEEtran LaTeX manuscript:
   - *Abstract* (≤ 200 words)
   - *Section 1: Introduction* (Contributions list)
   - *Section 2: Background & Threat Model*
   - *Section 3: System Architecture* (5 layers)
   - *Section 4: Mathematical Formulation* (Markov surprisal, PSI EWMA, Noisy-OR, $L_0$ search)
   - *Section 5: Implementation Details* (eBPF CO-RE, Rust/Python, cgroup v2)
   - *Section 6: Empirical Evaluation* (Tables 1–5 populated with real testbed data)
   - *Section 7: Discussion & Limitations* (honest scoping: hardware TPM, Kubernetes DaemonSet)
   - *Section 8: Related Work*
   - *Section 9: Conclusion*
2. Render high-resolution vector figures for architecture, sequence flow, and causal DAG.

### Phase 6: Internal Review & Submission (Weeks 7–8)
1. Execute pre-submission verification checklist.
2. Upload preprint to **arXiv cs.CR** for immediate academic priority.
3. Submit full manuscript to target venue (RAID 2027 / EuroSec 2027).

---

## 8. Critical Inquiries & Open Questions for the Author

To ensure alignment as we execute this transition, please consider and respond to the following key design questions:

1. **Testbed Hardware & Environment**:
   - Do you currently have an active Linux environment (Ubuntu 22.04 / Debian 12 / Kali with Kernel $\ge 5.15$) with root access where we can load eBPF probes and run `mpstat`/`perf` benchmarks, or should we prepare automated benchmark collection scripts for you to run on your VM?
2. **Sensor Implementation Path**:
   - Would you prefer to complete the sensor ring-buffer consumer in **Rust** (adding `libbpf-rs` or `aya` to `agent/`), or would you prefer a clean **Python-based `libbpf`/`bcc` sensor** that directly pipes kernel events into the existing FastAPI/worker pipeline?
3. **Target Submission Venue & Format**:
   - Are you targeting a **full conference paper (12–14 pages, IEEEtran)** for a systems security conference like **RAID 2027**, or a **short workshop paper (6–8 pages)** like **EuroSec 2027**?
4. **Dataset Validation Preference**:
   - Beyond our synthetic test-lab scenarios and live Linux workloads, would you be interested in evaluating Vajra against standard academic benchmark datasets such as **DARPA TC (Transparent Computing - CADETS / THEIA / TRACE)**?
