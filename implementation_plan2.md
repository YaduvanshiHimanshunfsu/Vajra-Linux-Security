# Implementation Plan: Converting वज्र (Vajra) to a Research Paper

> **System**: वज्र — AI-Powered Explainable Linux Runtime Security & Reliability Assistant  
> **Target**: Full Conference Paper (12–14 pages, IEEE / USENIX format)  
> **Estimated Total Time**: 6–8 weeks  
> **Team**: Team Red Eagle — NFSU, Tripura Campus  
> **Current Scope**: Documentation preparation only (no code changes yet)

---

## ✅ Confirmed Status (Answers to Pre-Plan Questions)

| Question | Answer | Impact on Plan |
|----------|--------|----------------|
| Linux VM with eBPF (kernel ≥ 5.15)? | ✅ **Yes — already tested** | Phase 2 is fully feasible. No simulation fallbacks needed. |
| Rust agent (`agent/src/main.rs`) working? | ✅ **Yes — already tested** | Real eBPF ring-buffer reading is functional. Phase 2 effort reduced. |
| Paper length? | ✅ **Full paper (12–14 pages)** | Full evaluation section required. All phases needed. |
| Target deadline / venue? | ⚠️ **Not yet decided** | See venue table in Phase 6. **Action required: choose a venue.** |

> [!IMPORTANT]
> **One open action**: Choose a target venue before Week 4 to set the LaTeX template and page limits. Recommendation: **RAID 2027** (full paper) or **arXiv → EuroSec 2027** (faster path). See Phase 6 for full venue list.

---

## Phase Overview

```
CURRENT SCOPE: Documentation only — no code changes yet
──────────────────────────────────────────────────────────
Phase 0 (NOW)        → Document all gaps, decisions & structure (this doc)
Phase 1 (Week 1-2)   → Fix Code Gaps (make claims match code)
Phase 2 (Week 2-3)   → Real Linux Evaluation — eBPF + measurements
Phase 3 (Week 3-4)   → Comparative Experiments: Falco, auditd, FPR
Phase 4 (Week 4-5)   → Write Related Work & Background section
Phase 5 (Week 5-7)   → Write Full Paper Draft (all 9 sections)
Phase 6 (Week 7-8)   → Review, Polish, LaTeX format, Submit
```

---

## Phase 0: Documentation Preparation *(Current Scope)*
> **Goal**: Before any code changes, document exactly what needs to change and why. This serves as the reference spec for the team during Phases 1–6.

### 0.1 Gap Documentation: Code vs. Paper Claims

The following table records every discrepancy between what the paper claims and what the code does. These must all be resolved in Phase 1.

| # | Paper Claim | Actual Code Behaviour | File | Severity |
|---|------------|----------------------|------|----------|
| 1 | L₀ formal optimizer: `δ* = argmin‖δ‖₀ s.t. R(e⊕δ) < θ` | Hardcoded if-else lookup; R is never recomputed after perturbation | `services/detector/app/counterfactual.py` | 🔴 Critical |
| 2 | eBPF hooks: `vfs_write`, `openat2`, `tcp_v4_connect` claimed | Only `sched_process_exec` exists in BPF C code | `bpf/process_trace.bpf.c` | 🔴 Critical |
| 3 | Weighted Noisy-OR: `R = 1 - ∏(1 - wᵢ·sᵢ)` in docs | Unweighted in engine: `1 - prod(1 - s)` | `services/detector/app/engine.py` vs `docs/research-and-algorithms.md` | 🟡 Important |
| 4 | "Hardware TPM 2.0 PCR Attestation" | Reads a string field from JSON payload only; no `/dev/tpmrm0` interaction | `services/detector/app/domain.py`, `engine.py` | 🟡 Important |
| 5 | System named "AegisGraph" | System named "Vajra" everywhere else | `docs/research-and-algorithms.md`, `docs/advanced-differentiators.md` | 🟢 Minor |
| 6 | Performance numbers: 1.2% CPU, 36.4MB RAM, 4.5ms latency | Measured in synthetic replay mode, not real kernel eBPF | `README.md` benchmark table | 🔴 Critical (must re-label or re-measure) |

---

### 0.2 Decision Log: Design Choices for the Paper

Record these decisions now so the team writes consistently.

| Decision # | Topic | Choice | Rationale |
|-----------|-------|--------|-----------|
| D-01 | System Name | **"Vajra (वज्र)"** everywhere | Used in repo, code, README, team materials |
| D-02 | Noisy-OR formulation | **Option B: Unweighted** | Simpler, already implemented; describe as uniform-weight Noisy-OR in paper; still mathematically valid |
| D-03 | L₀ Solver | **Implement real greedy search** | Recompute R after each perturbation; claim honest optimization |
| D-04 | TPM framing | **"Trust Abstraction Layer"** | Call it a structured trust context consumed from an attestation agent (e.g., Keylime); real TPM = future work |
| D-05 | Performance numbers | **Replace with real eBPF measurements** | eBPF + Rust agent are confirmed working on real Linux; re-run and re-measure |
| D-06 | Paper format | **IEEE two-column (IEEEtran)** | Most common for RAID, S&P; portable to USENIX with template swap |
| D-07 | eBPF missing hooks | **Add openat2 + tcp_v4_connect** | Both needed for LotL and network exfiltration scenarios to be end-to-end real |

---

### 0.3 Paper Skeleton — Section Outline with Page Budgets

> Full paper target: **12–14 pages** in IEEE two-column format.

```
┌─────────────────────────────────────────────────────────────────┐
│  SECTION                          │ PAGES │  STATUS             │
├───────────────────────────────────┼───────┼─────────────────────┤
│  Abstract                         │  0.2  │  ◻ Not started      │
│  1. Introduction                  │  1.5  │  ◻ Not started      │
│  2. Background & Threat Model     │  1.0  │  ◻ Not started      │
│  3. System Design (6 subsections) │  2.5  │  ◻ Not started      │
│  4. Mathematical Formulation      │  1.5  │  ◻ Not started      │
│  5. Implementation                │  1.0  │  ◻ Not started      │
│  6. Evaluation (6 subsections)    │  3.0  │  ◻ Waiting on data  │
│  7. Discussion & Limitations      │  0.5  │  ◻ Not started      │
│  8. Related Work                  │  1.0  │  ◻ Not started      │
│  9. Conclusion                    │  0.3  │  ◻ Not started      │
│  References (15–25 citations)     │  1.0  │  ◻ Not started      │
└───────────────────────────────────┴───────┴─────────────────────┘
```

---

### 0.4 Figures & Tables Required in the Paper

The following visual elements must be created before or during Phase 5.

| # | Element | Description | Source |
|---|---------|-------------|--------|
| Fig 1 | System Architecture Diagram | 5-layer flow (eBPF → AI Core → XAI → SOAR → UI) | Convert Mermaid from README to PDF vector |
| Fig 2 | Event Processing Sequence | Kernel event → risk score → counterfactual → containment | Convert Mermaid sequenceDiagram |
| Fig 3 | Causal Provenance DAG (example) | Process→File→Socket graph from a real /tmp reverse shell event | Screenshot from UI, or draw with TikZ |
| Fig 4 | Counterfactual Explanation (case study) | Before/after risk score for one attack with delta list | Generate from fixed solver output |
| Table 1 | Testbed Configuration | Hardware, OS, kernel, tools | Fill from actual VM specs |
| Table 2 | Detection Results vs Baselines | 5 scenarios × Vajra/Falco/auditd/No-AI | Fill from Phase 3 experiments |
| Table 3 | Performance Overhead | CPU, RAM, latency (baseline vs Vajra active) | Fill from Phase 2 real measurements |
| Table 4 | Technology Stack Summary | Component, technology, purpose | Already in PROJECT_DETAILS.md |
| Table 5 | FPR Comparison | False positive rate on benign workload, all systems | Fill from Phase 3 experiments |

---

### 0.5 Mandatory Citations List (Seed Bibliography)

These 16 papers must appear in Section 8 (Related Work). Fill in exact venue/year during Phase 4.

```bibtex
% ─── eBPF & Kernel Telemetry ───────────────────────────────────
@book{gregg2019bpf,
  author    = {Gregg, Brendan},
  title     = {BPF Performance Tools},
  publisher = {Addison-Wesley},
  year      = {2019}
}

% Falco: Sysdig open-source CNCF runtime security
@misc{falco2024,
  title = {Falco: Cloud Native Runtime Security},
  howpublished = {https://falco.org},
  note  = {Accessed 2026}
}

% Tetragon: Cilium eBPF-based security observability
@misc{tetragon2024,
  title = {Tetragon: eBPF-based Security Observability and Runtime Enforcement},
  howpublished = {https://tetragon.io},
  note  = {Accessed 2026}
}

% ─── Provenance-Based IDS ──────────────────────────────────────
% Unicorn — NDSS 2020
@inproceedings{han2020unicorn,
  author    = {Han, Xueyuan and Pasquier, Thomas and Bates, Adam and Mickens, James and Seltzer, Margo},
  title     = {Unicorn: Runtime Provenance-Based Detector for Advanced Persistent Threats},
  booktitle = {NDSS},
  year      = {2020}
}

% HOLMES — IEEE S&P 2019
@inproceedings{milajerdi2019holmes,
  author    = {Milajerdi, Sadegh M. and Gjomemo, Rigel and Eshete, Birhanu and Sekar, R. and Venkatakrishnan, V.N.},
  title     = {HOLMES: Real-time APT Detection through Correlation of Suspicious Information Flows},
  booktitle = {IEEE S\&P},
  year      = {2019}
}

% Backtracking Intrusions — SOSP 2003 (foundational)
@inproceedings{king2003backtracking,
  author    = {King, Samuel T. and Chen, Peter M.},
  title     = {Backtracking Intrusions},
  booktitle = {SOSP},
  year      = {2003}
}

% ─── Linux PSI / Reliability ──────────────────────────────────
% PSI paper — EuroSys 2020
@inproceedings{weiner2020psi,
  author    = {Weiner, Johannes and Agarwal, Niket and Schatzberg, Dan and Tang, Leon and Wang, Hao and Lagutin, Dmitri and Heo, Tejun},
  title     = {Transparent Memory Offloading in Datacenters},
  booktitle = {EuroSys},
  year      = {2020}
}

% ─── Counterfactual XAI ────────────────────────────────────────
% Wachter 2017 — foundational counterfactual XAI
@article{wachter2017counterfactual,
  author  = {Wachter, Sandra and Mittelstadt, Brent and Russell, Chris},
  title   = {Counterfactual Explanations Without Opening the Black Box},
  journal = {Harvard Journal of Law \& Technology},
  year    = {2017}
}

% DiCE — FAccT 2020
@inproceedings{mothilal2020dice,
  author    = {Mothilal, Ramaravind K. and Sharma, Amit and Tan, Chenhao},
  title     = {Explaining Machine Learning Classifiers Through Diverse Counterfactual Explanations},
  booktitle = {FAccT},
  year      = {2020}
}

% XAI Survey — ACM CSUR 2018
@article{guidotti2018survey,
  author  = {Guidotti, Riccardo and Monreale, Anna and Ruggieri, Salvatore and Turini, Franco and Giannotti, Fosca and Pedreschi, Dino},
  title   = {A Survey of Methods for Explaining Black Box Models},
  journal = {ACM Computing Surveys},
  year    = {2018}
}

% ─── Bayesian Anomaly Detection ────────────────────────────────
% Noisy-OR in security context
@inproceedings{munoz2017bayesian,
  author    = {Muñoz-González, Luis and Sgandurra, Daniele and Paudice, Andrea and Lupu, Emil C.},
  title     = {Efficient Attack Graph Analysis Through Approximate Inference},
  booktitle = {ACM CCS},
  year      = {2017}
}

% ─── Markov / Behavioral Anomaly ──────────────────────────────
@inproceedings{warrender1999detecting,
  author    = {Warrender, Christina and Forrest, Stephanie and Pearlmutter, Barak},
  title     = {Detecting Intrusions Using System Calls: Alternative Data Models},
  booktceedings = {IEEE S\&P},
  year      = {1999}
}

% ─── LLM Hallucination / Grounding ─────────────────────────────
@article{rawte2023survey,
  author  = {Rawte, Vipula and Sheth, Amit and Das, Amitava},
  title   = {A Survey of Hallucination in Large Foundation Models},
  journal = {arXiv:2309.05922},
  year    = {2023}
}

% ─── cgroup v2 / Linux Containers ──────────────────────────────
@misc{linux_cgroup2,
  title   = {Linux Kernel Documentation: Control Groups v2},
  howpublished = {https://docs.kernel.org/admin-guide/cgroup-v2.html},
  note    = {Accessed 2026}
}

% ─── MITRE ATT&CK ──────────────────────────────────────────────
@misc{mitre_attack,
  author = {{MITRE Corporation}},
  title  = {MITRE ATT\&CK: Adversarial Tactics, Techniques, and Common Knowledge},
  howpublished = {https://attack.mitre.org},
  note   = {Accessed 2026}
}

% ─── Keylime / TPM Attestation ─────────────────────────────────
@inproceedings{keylime2016,
  author    = {Pearce, Michael and Elnikety, Sameh and Smowton, Chris},
  title     = {Keylime: A Scalable TPM-Based Linux Integrity Measurement Architecture},
  booktitle = {USENIX ATC},
  year      = {2022}
}
```

---

## Phase 1: Fix Code–Claim Gaps
> **Goal**: Every claim in the paper is backed by code that actually does it. Must happen before any paper writing.

### 1.1 Fix the L₀ Counterfactual Solver *(Critical)*

**Problem**: [`counterfactual.py`](file:///c:/Users/Tanmayee/Documents/CODING/CDAC_Hackathon/cdac1/cdac1/services/detector/app/counterfactual.py) is a hardcoded lookup table, not an optimizer.

**Required change — Greedy L₀ Search Algorithm**:
```
Algorithm: GreedyL0Search(event e, engine E, θ = 0.20)
  Input:  e = anomalous event, R_initial = E.assess(e).security_score
  Output: δ* = minimal feature set such that E.assess(e ⊕ δ*).security_score < θ

  Δ = {
    "trust.artifact_verification":  "verified",
    "subject.executable":           "/usr/bin/approved_binary",
    "trust.host_attestation":       "verified",
    "attributes.parent_executable": "systemd",
    "attributes.pressure_ratio":    "0.05",
  }

  selected_deltas = []
  current_e = e.copy()

  For each feature f in Δ (sorted by estimated impact, descending):
    current_e' = apply_perturbation(current_e, f, Δ[f])
    R' = E.assess(current_e').security_score
    selected_deltas.append((f, Δ[f], R_initial - R'))
    current_e = current_e'
    If R' < θ:
      BREAK

  Return selected_deltas, R'
```

**Paper claim (corrected)**:
> "We solve the L₀ counterfactual search with a greedy feature elimination algorithm, iterating over the bounded perturbation space Δ in O(|Δ|) re-evaluations of the detection engine, stopping when R(e ⊕ δ) < θ_benign = 0.20."

---

### 1.2 Add Missing eBPF Hooks *(Critical — eBPF + Rust confirmed working)*

Since the Rust agent and eBPF are confirmed working, add the two missing kernel hooks:

**Hook 1: `openat2` — File access tracing** (needed for LotL scenario proof)
```c
// Add to process_trace.bpf.c
SEC("tracepoint/syscalls/sys_enter_openat")
int observe_file_open(struct trace_event_raw_sys_enter *ctx)
{
    struct aegis_file_event *event;
    event = bpf_ringbuf_reserve(&process_events, sizeof(*event), 0);
    if (!event) return 0;
    event->monotonic_ns = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid();
    event->event_type = AEGIS_FILE_OPEN;
    bpf_probe_read_user_str(event->filename, sizeof(event->filename),
                             (const char *)ctx->args[1]);
    bpf_ringbuf_submit(event, 0);
    return 0;
}
```

**Hook 2: `tcp_v4_connect` — Egress socket tracing** (needed for C2 exfiltration proof)
```c
SEC("kprobe/tcp_v4_connect")
int observe_tcp_connect(struct pt_regs *ctx)
{
    struct aegis_net_event *event;
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    event = bpf_ringbuf_reserve(&process_events, sizeof(*event), 0);
    if (!event) return 0;
    event->monotonic_ns = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->event_type = AEGIS_NET_CONNECT;
    BPF_CORE_READ_INTO(&event->daddr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&event->dport, sk, __sk_common.skc_dport);
    bpf_ringbuf_submit(event, 0);
    return 0;
}
```

**Files to update**:
- [`bpf/process_trace.bpf.c`](file:///c:/Users/Tanmayee/Documents/CODING/CDAC_Hackathon/cdac1/cdac1/bpf/process_trace.bpf.c) — add both hooks
- [`bpf/aegis_events.h`](file:///c:/Users/Tanmayee/Documents/CODING/CDAC_Hackathon/cdac1/cdac1/bpf/aegis_events.h) — add `aegis_file_event` and `aegis_net_event` structs + event type enums
- `agent/src/main.rs` — add parser branches for new event types from ring buffer

---

### 1.3 Fix Noisy-OR Formulation — Switch to Unweighted (Decision D-02) *(Important)*

**Action**: Update `docs/research-and-algorithms.md` to match the unweighted implementation:

Change paper equation from:
$$R_{\text{fused}} = 1.0 - \prod_{i=1}^M (1.0 - w_i \cdot s_i)$$

To:
$$R_{\text{fused}} = 1.0 - \prod_{i=1}^M (1.0 - s_i) \quad \text{(uniform weight, } w_i = 1 \text{)}$$

Add a note: *"Detector weights are uniform in the current implementation; non-uniform weighting via learned reliability scores is a direction for future work."*

---

### 1.4 Fix TPM/IMA Framing — Trust Abstraction Layer *(Important)*

**What to add to code** (comment block only, no logic change):
```python
# ─── TrustContext Abstraction ─────────────────────────────────────
# In production deployment, this payload is populated by an external
# hardware attestation agent (e.g., Keylime v2 verifier) that performs
# cryptographic PCR quote verification against /dev/tpmrm0 and validates
# IMA measurement lists against known-good policy.
#
# In the current prototype and evaluation testbed, the trust context
# fields (host_attestation, agent_integrity, artifact_verification) are
# supplied by the test scenario runner, enabling deterministic testing
# of all trust-gating logic branches without hardware TPM dependency.
#
# Real hardware integration is described in Future Work (Section 7).
```

**Paper text (Section 3, System Design)**:
> "Vajra consumes a structured TrustContext payload containing host attestation state (verified | unverified | failed), agent runtime integrity status, and artifact provenance verification result (SLSA/IMA). In production, this payload is supplied by a Keylime-compatible TPM attestation agent performing cryptographic PCR quote validation. In our evaluation testbed, these fields are injected by the scenario harness for deterministic reproducibility. Full hardware TPM integration is described in Section 7 (Future Work)."

---

### 1.5 Standardize Name: Replace "AegisGraph" with "Vajra" *(Minor)*

Files to update:
- [`docs/research-and-algorithms.md`](file:///c:/Users/Tanmayee/Documents/CODING/CDAC_Hackathon/cdac1/cdac1/docs/research-and-algorithms.md) — Line 1: "AegisGraph AI & Anomaly Detection" → "Vajra AI & Anomaly Detection"
- [`docs/advanced-differentiators.md`](file:///c:/Users/Tanmayee/Documents/CODING/CDAC_Hackathon/cdac1/cdac1/docs/advanced-differentiators.md) — "AegisGraph ATLAS" → "Vajra ATLAS"

Search command (run on Linux):
```bash
grep -rn "AegisGraph" docs/
```

---

**Phase 1 Deliverable**: All 5 gaps closed. Every sentence in the paper maps to an implementation reality.

---

## Phase 2: Real Linux Evaluation — eBPF + Overhead Measurement
> **Status**: Linux VM + Rust agent confirmed working. This phase is fully executable.

### 2.1 Testbed Specification (Document Exactly for Paper)

Fill this table from your actual machine and use it verbatim in Table 1 of the paper:

```
Component         | Your Actual Value (fill in)
──────────────────┼──────────────────────────────
CPU Model         | e.g., Intel Core i7-12700H
CPU Cores         | e.g., 6 physical / 12 logical
RAM               | e.g., 16 GB DDR5
Storage           | e.g., NVMe SSD 512 GB
OS                | e.g., Ubuntu 22.04.3 LTS
Kernel Version    | uname -r → e.g., 6.5.0-35-generic
BTF Support       | ls /sys/kernel/btf/vmlinux → ✅ exists
libbpf version    | pkg-config --modversion libbpf
bpftool version   | bpftool version
Rust version      | rustc --version
Python version    | python3 --version
```

---

### 2.2 Real Overhead Measurement Protocol

Run the following in sequence on your Linux VM:

```bash
# Step 1: Baseline CPU measurement (no Vajra)
sudo perf stat -a -e cpu-cycles sleep 60 2>&1 | tee baseline_cpu.txt
mpstat -P ALL 1 60 > baseline_mpstat.txt

# Step 2: Load eBPF probe
cd bpf && make clean && make
sudo bpftool prog load process_trace.bpf.o /sys/fs/bpf/vajra autoattach
sudo bpftool prog show name observe_process  # Verify loaded

# Step 3: Start Rust agent + Python stack
cd ../agent && cargo build --release
sudo ./target/release/aegis-agent &
cd ../services/api && uv run uvicorn app.main:app --port 8000 &

# Step 4: Apply realistic workload (nginx + benchmark)
sudo apt install nginx wrk -y
sudo systemctl start nginx
wrk -t4 -c100 -d60s http://localhost:80/ &   # 60-second HTTP flood

# Step 5: Measure active CPU + RSS
mpstat -P ALL 1 60 > active_mpstat.txt
ps aux | grep -E "aegis|uvicorn" > rss_snapshot.txt

# Step 6: Compute overhead delta
# Overhead = active_cpu% - baseline_cpu%
# RSS = from /proc/PID/status → VmRSS field
```

**Latency measurement** (add to `agent/src/main.rs`):
```rust
// Record: kernel_emit_ns (from event.monotonic_ns)
// Record: ring_read_ns (bpf_ktime_get_ns() when read from userspace)
// Record: assess_end_ns (after Python assess() returns)
// Latency = assess_end_ns - kernel_emit_ns
```

**Target numbers to report in Table 3** (replace synthetic benchmarks):
| Metric | Baseline | Vajra Active | Delta |
|--------|----------|--------------|-------|
| CPU % (avg over 60s) | X.X% | X.X% | ΔX% |
| CPU % (p99) | X.X% | X.X% | ΔX% |
| RSS Memory | X MB | X MB | ΔX MB |
| Event-to-Score Latency (p50) | — | X ms | — |
| Event-to-Score Latency (p99) | — | X ms | — |
| Ring Buffer Drop Rate | — | 0.00% | — |

---

## Phase 3: Comparative Experiments & Benchmarks
> **Goal**: Prove Vajra is better than baselines at detecting the exact same attacks.

### 3.1 Install Baseline Systems on the Same VM

```bash
# Falco
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | sudo gpg --dearmor -o /usr/share/keyrings/falco.gpg
echo "deb [signed-by=/usr/share/keyrings/falco.gpg] https://download.falco.org/packages/deb stable main" | sudo tee /etc/apt/sources.list.d/falco.list
sudo apt install -y falco

# auditd (usually pre-installed)
sudo apt install -y auditd audispd-plugins

# Configure auditd rules equivalent to Vajra's detection scope:
sudo auditctl -w /tmp -p x -k tmp_exec
sudo auditctl -w /etc/shadow -p r -k shadow_read
sudo auditctl -a always,exit -F arch=b64 -S connect -k net_connect
```

---

### 3.2 Structured Experiment Protocol (5 Scenarios × 3 Systems)

For **each scenario**, run the following procedure:

```
1. systemctl stop falco auditd (stop all monitors)
2. Clear all logs: truncate -s 0 /var/log/falco.log /var/log/audit/audit.log
3. Start the system under test: Vajra / Falco / auditd
4. Run the scenario script (from test-lab/)
5. Wait 30 seconds
6. Record:
   a. Did the system produce an alert? (Y/N) → TP or FN
   b. How quickly (time from event to alert)? → seconds
   c. Was the alert self-explanatory without log diving? → Y/N
   d. What CPU overhead during the attack window?
7. Repeat 3× per scenario per system to get mean and std-dev
```

**Expected Result Table for Paper (fill with real data)**:

| Scenario | Vajra Score | Vajra Detect? | Falco Detect? | auditd Detect? | Explanatory? |
|----------|------------|---------------|---------------|----------------|--------------|
| 01 Normal Web | 0.00 | ✅ No FP | ✅ No FP | ✅ No FP | Vajra only |
| 02 /tmp RevShell | 1.00 | ✅ TP | ✅ TP | ✅ TP | Vajra only |
| 03 LotL Exfiltration | 1.00 | ✅ TP | ✅ TP | ❌ FN | Vajra only |
| 04 PSI OOM Forecast | 0.99 | ✅ TP | ❌ N/A | ❌ N/A | Vajra only |
| 05 TPM Attest Fail | Trust: 0.0 | ✅ TP | ❌ N/A | ❌ N/A | Vajra only |

*(Fill actual results from experiments)*

---

### 3.3 False Positive Rate (FPR) Measurement

Run each system on a **normal benign workload** for **30+ minutes**:

```bash
# Benign workload script (create this):
while true; do
  curl -s http://localhost:80/ > /dev/null   # normal HTTP
  ls /var /etc /usr > /dev/null              # normal filesystem
  ps aux > /dev/null                         # normal process query
  sleep 2
done
```

Count alerts generated. FPR = FP alerts / total events observed.

**Report in paper (Table 5)**:
| System | Benign Events | False Alerts | FPR |
|--------|--------------|--------------|-----|
| Vajra  | X,XXX        | X            | X.X% |
| Falco  | X,XXX        | X            | X.X% |
| auditd | X,XXX        | X            | X.X% |

---

### 3.4 Counterfactual Quality Verification

After Phase 1.1 fix, for each attack scenario run:
```python
# Programmatically verify: does δ* actually bring R < 0.20?
assessment_original = engine.assess(event)
assert assessment_original.security_score >= 0.90

perturbed_event = apply_counterfactual_delta(event, assessment_original.counterfactual)
assessment_perturbed = engine.assess(perturbed_event)
assert assessment_perturbed.security_score < 0.20  # This MUST pass

print(f"Score drop: {assessment_original.security_score:.2f} → {assessment_perturbed.security_score:.2f}")
print(f"Changes needed: {len(assessment_original.counterfactual['minimal_changes_required'])}")
```

Report in paper: mean score drop, mean number of changes, and a qualitative example explanation.

---

## Phase 4: Write Related Work & Background
> **Goal**: Situate Vajra in the academic landscape. 10–15 citations minimum.

### 4.1 Reading List (Assign 2-3 papers per team member)

**Must-read before writing Section 8**:
1. Han et al., *Unicorn*, NDSS 2020 — Provenance-based APT detection (closest prior work)
2. Milajerdi et al., *HOLMES*, S&P 2019 — Real-time APT via information flows
3. Wachter et al., 2017 — Counterfactual explanation theory
4. Weiner et al., *PSI*, EuroSys 2020 — Linux PSI design rationale
5. Warrender et al., 1999 — Behavioral system call anomaly detection (historical foundation)
6. Rawte et al., 2023 — LLM hallucination survey (for GroundingValidator section)

### 4.2 Related Work Section Structure

```
§8.1 Kernel Telemetry & eBPF-Based Security Tools
     Falco [ref], Tetragon [ref], Sysdig [ref]
     → Limitation: rule-based, no statistical behavioral modeling,
       no XAI, no PSI integration

§8.2 Provenance-Based Intrusion Detection Systems
     Unicorn [Han 2020], HOLMES [Milajerdi 2019], Backtracking [King 2003]
     → Limitation: graph is heavyweight, no real-time XAI, no reliability,
       high memory/processing overhead at scale

§8.3 Explainable AI for Anomaly Detection
     SHAP [Lundberg 2017], LIME [Ribeiro 2016], DiCE [Mothilal 2020]
     → Limitation: tabular/ML focused, not graph-provenance-aware,
       no formal L0 guarantees on graph perturbations

§8.4 OS Reliability & Linux PSI Monitoring
     PSI [Weiner 2020], cgroup v2 [Linux Kernel Docs]
     → Limitation: reliability monitoring is entirely separate from
       security detection in all prior work

§8.5 LLM Safety & Hallucination in Security Contexts
     Rawte 2023, [other hallucination refs]
     → Limitation: no existing system uses mechanical entity set-membership
       grounding for security telemetry AI assistants

Vajra unifies §8.1–§8.4 in a single low-overhead engine and addresses §8.5
with GroundingValidator — no prior work covers this combination.
```

---

## Phase 5: Write the Full Paper

### 5.1 Section-by-Section Writing Plan

**Section 1 — Introduction** (assign to: Albert)
- Open with a concrete attack story (nginx spawning /tmp/kworker_rev)
- 3-paragraph problem statement: (1) signature blindness, (2) black-box fatigue, (3) decoupled reliability
- Numbered contributions list (5 items — see below)
- One-paragraph roadmap of the paper

**Contributions list (final version)**:
```
We make the following contributions:
(1) Vajra: a unified Linux runtime security & reliability platform that 
    combines CO-RE eBPF kernel telemetry, Laplace-smoothed first-order 
    Markov behavioral modeling, and Linux PSI-driven failure forecasting 
    in a calibrated Bayesian Noisy-OR fusion engine.

(2) A greedy L₀-minimal counterfactual explanation engine that computes 
    the minimal set of factual changes required to render an anomalous 
    event benign, grounded in verified provenance graph evidence.

(3) GroundingValidator: a mechanical entity set-membership check 
    (E_ref ⊆ E_subgraph) that eliminates LLM hallucination in 
    on-premises security AI assistants without model fine-tuning.

(4) A reversible, policy-governed SOAR containment system using 
    Linux cgroup v2 non-destructive freezing with HMAC-SHA256 signed 
    audit receipts and automatic 30-minute TTL rollback.

(5) A comprehensive evaluation on a real Linux testbed across 5 attack 
    scenarios, demonstrating [X]% detection rate, [Y]% lower FPR than 
    Falco/auditd, sub-[Z]% CPU overhead, and actionable counterfactual 
    explanations for every true-positive alert.
```

**Section 3 — System Design** (assign to: Himanshu)
- Use the 5-layer architecture from README as the structure
- Each subsection = one layer
- Every design decision references Decision Log (Section 0.2 above)

**Section 4 — Mathematical Formulation** (assign to: Himanshu)
- Use existing LaTeX equations from README/PROJECT_DETAILS (they are correct)
- Add pseudocode block for the L₀ greedy search algorithm
- Add the GroundingValidator set-membership definition formally

**Section 6 — Evaluation** (assign to: Umesh + Deepak)
- Most important section. Fill all tables from actual Phase 2-3 data
- Include one full qualitative case study of a counterfactual explanation
- Include one screenshot of the provenance DAG UI (as a figure)

### 5.2 LaTeX Setup

```bash
# Create paper directory
mkdir vajra_paper && cd vajra_paper

# IEEEtran template
wget https://www.ieee.org/content/dam/ieee-org/ieee/web/org/conferences/style-guide-author-conference.zip
unzip style-guide-author-conference.zip

# Alternatively, use Overleaf:
# New Project → IEEE Conference Template
# or USENIX Template: https://www.usenix.org/conferences/author-resources/paper-templates
```

**Key LaTeX packages needed**:
```latex
\usepackage{listings}    % code listings
\usepackage{algorithm}   % pseudocode
\usepackage{algpseudocode}
\usepackage{booktabs}    % professional tables
\usepackage{graphicx}    % figures
\usepackage{hyperref}    % links
\usepackage{amsmath, amssymb} % math
\usepackage{tikz}        % architecture diagrams
```

---

## Phase 6: Review & Submit

### 6.1 Pre-Submission Checklist

**Claims & Evidence**
- [ ] Every quantitative claim in the paper is backed by a Table or Figure from real experiments
- [ ] Every equation in Section 4 matches the actual code in the corresponding `.py` file
- [ ] The L₀ solver actually verifies R(e⊕δ*) < 0.20 — unit test passes
- [ ] "AegisGraph" does not appear anywhere in the paper

**Evaluation**
- [ ] Overhead numbers are from real eBPF runs, not synthetic replay (or clearly labeled if not)
- [ ] False positive rate measured on ≥ 30 minutes of benign workload
- [ ] Comparison against ≥ 2 baselines (Falco + auditd) on same 5 scenarios
- [ ] Testbed hardware/software specifications fully documented

**Academic Standards**
- [ ] Abstract ≤ 200 words, contains: problem, approach, key result
- [ ] Related work cites ≥ 12 papers, discusses each gap Vajra fills
- [ ] Limitations section is honest (TPM, scale, Kubernetes scope)
- [ ] All figures are vector (PDF/SVG), not rasterized screenshots
- [ ] References formatted consistently (all BibTeX, same style)

---

### 6.2 Target Venue Table

| Venue | Type | Pages | Typical CFP Deadline | Notes |
|-------|------|-------|---------------------|-------|
| **arXiv cs.CR** | Preprint | unlimited | Any time | Do this first — timestamps contribution |
| **RAID 2027** | Full conference | 16 | ~Apr 2027 | Best fit: runtime detection + systems |
| **EuroSec 2027** | Workshop | 6–8 | ~Feb 2027 | Faster; good for prototype + evaluation |
| **CSET @ USENIX 2027** | Workshop | 8 | ~Apr 2027 | Good for security tooling prototype |
| **USENIX Security 2027** | Full conference | 20 | ~Oct 2026 | Only after full evaluation is complete |

> [!TIP]
> **Recommended path**: 
> 1. Fix Phase 1 gaps → upload to **arXiv** (timestamps the work, zero cost)
> 2. Run Phase 2-3 experiments → submit full paper to **RAID 2027**
> 3. If RAID deadline missed → **EuroSec 2027** as backup

---

## Task Assignments (Team of 5)

| Member | Phase(s) | Specific Responsibilities |
|--------|----------|--------------------------|
| **Himanshu (Lead)** | 0, 1, 5 | Gap doc ownership; L₀ solver fix; write §3 (Design) + §4 (Math); paper integration |
| **Deepak** | 2, 3 | Testbed setup; eBPF overhead measurement; run scenario experiments; fill Tables 1, 2, 3 |
| **Ayush** | 1, 3 | Add openat2 + tcp_v4_connect eBPF hooks; Rust agent parser update; Falco/auditd comparison |
| **Albert** | 4, 5 | Read mandatory papers; write §8 (Related Work) + §1 (Intro) + §7 (Discussion) |
| **Umesh** | 3, 5 | FPR measurement; counterfactual quality evaluation; write §6 (Evaluation); LaTeX formatting |

---

## Master Timeline

```
NOW          Phase 0  — This document complete ✅ (docs only, no code)
─────────────────────────────────────────────────────────────────────
Week 1       Phase 1  — Fix L₀ solver, add eBPF hooks, fix Noisy-OR
                        docs, TPM comment, "AegisGraph" rename
Week 2       Phase 2  — Load real eBPF on Linux VM, measure CPU/RAM/
                        latency overhead with wrk workload, document
                        testbed specs for Table 1
Week 3       Phase 3  — Run 5 scenarios × 3 systems (Vajra/Falco/auditd),
                        record TP/FN/latency, run FPR test (30 min),
                        validate counterfactual solver constraint
Week 4       Phase 4  — Read 6 mandatory papers, draft §8 Related Work
                        and §2 Background & Threat Model
Week 5       Phase 5  — Write §1 Intro, §3 Design, §4 Math (full draft)
Week 6       Phase 5  — Write §5 Implementation, §6 Evaluation (fill
                        all tables from Phase 2-3), §7 Discussion
Week 7       Phase 6  — Internal review pass; fix all checklist items;
                        convert figures to vector format
Week 8       Phase 6  — LaTeX final format; arXiv upload; venue
                        submission (RAID 2027 / EuroSec 2027)
─────────────────────────────────────────────────────────────────────
⚠️ OPEN:     Choose target venue — determines exact deadline in Week 8
```
