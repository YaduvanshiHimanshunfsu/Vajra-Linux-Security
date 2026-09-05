# Implementation Plan: Converting वज्र (Vajra) to a Research Paper

> **System**: वज्र — AI-Powered Explainable Linux Runtime Security & Reliability Assistant  
> **Target**: Peer-reviewed research paper  
> **Estimated Total Time**: 6–8 weeks  
> **Team**: Team Red Eagle (NFSU Tripura)

---

## Phase Overview

```
Phase 1 (Week 1-2)   → Fix Code Gaps (make claims match code)
Phase 2 (Week 2-3)   → Real Linux Evaluation Setup
Phase 3 (Week 3-4)   → Comparative Experiments & Benchmarks
Phase 4 (Week 4-5)   → Write Related Work & Background
Phase 5 (Week 5-7)   → Write the Paper (full draft)
Phase 6 (Week 7-8)   → Review, Polish, Submit
```

---

## Phase 1: Fix Code–Claim Gaps
> **Goal**: Make the codebase match every claim in the paper. This is non-negotiable for peer review.

### 1.1 Fix the L₀ Counterfactual Solver *(Critical)*
**Current problem**: `counterfactual.py` is a hardcoded if-else lookup. The paper claims a formal optimizer.

**Task — Implement a real greedy L₀ search**:
```
For each feature f in the feature set Δ:
  1. Create perturbed event e' = e ⊕ {flip f}
  2. Re-evaluate full engine: R' = DetectionEngine.assess(e')
  3. If R' < θ_benign (0.20): record f as minimal delta, stop
  4. Else: add f to the change set and continue
Output: minimal set of features needed to flip verdict
```

- **File to modify**: [`services/detector/app/counterfactual.py`](file:///c:/Users/Tanmayee/Documents/CODING/CDAC_Hackathon/cdac1/cdac1/services/detector/app/counterfactual.py)
- **Test**: After each perturbation, call `DetectionEngine.assess()` and verify R drops below 0.20
- **Paper claim fix**: "We solve L₀ via a greedy feature-elimination search, iterating over the bounded feature space Δ in O(|Δ|) engine evaluations."

---

### 1.2 Add Missing eBPF Hooks *(Critical)*
**Current problem**: `process_trace.bpf.c` only has `sched_process_exec`. The docs claim `vfs_write`, `openat2`, `tcp_v4_connect`.

**Tasks**:
- [ ] Add `openat2` / `vfs_open` tracepoint to `process_trace.bpf.c` for file access detection
- [ ] Add `tcp_v4_connect` kprobe for egress socket tracking
- [ ] Update `aegis_events.h` struct to hold file path and socket IP/port
- [ ] Update `agent/src/main.rs` Rust reader to parse new event types from ring buffer

**Files to modify**:
- [`bpf/process_trace.bpf.c`](file:///c:/Users/Tanmayee/Documents/CODING/CDAC_Hackathon/cdac1/cdac1/bpf/process_trace.bpf.c)
- [`bpf/aegis_events.h`](file:///c:/Users/Tanmayee/Documents/CODING/CDAC_Hackathon/cdac1/cdac1/bpf/aegis_events.h)
- `agent/src/main.rs`

> [!IMPORTANT]
> If time is very limited: add at least `openat2` (needed for LotL scenario validation). Document `tcp_v4_connect` as "implemented via user-space replay in current prototype, kernel hook in progress" — reviewers accept honest scoping.

---

### 1.3 Fix Noisy-OR Weighted vs Unweighted Discrepancy *(Important)*
**Current problem**: `engine.py` uses unweighted Noisy-OR; `docs/research-and-algorithms.md` specifies weighted.

**Option A (Recommended)**: Add per-detector weights to the engine:
```python
# In engine.py: _fuse(scores, weights)
# Default weights: rule=1.0, markov=0.90, psi=0.85, trust=1.0
R = 1 - prod((1 - w*s) for w, s in zip(weights, scores))
```
- **File to modify**: [`services/detector/app/engine.py`](file:///c:/Users/Tanmayee/Documents/CODING/CDAC_Hackathon/cdac1/cdac1/services/detector/app/engine.py)

**Option B (Simpler)**: Change the paper math to match the unweighted implementation. Document it as uniform-weight Noisy-OR — still valid.

---

### 1.4 Fix TPM/IMA Framing *(Important)*
**Current problem**: Called "Hardware TPM 2.0 Attestation" but it only reads a JSON field.

**Task**: Add a clear abstraction boundary in code and paper:
- Rename the struct to `TrustContextPayload` or add a comment block:
  ```python
  # TrustContext: In production, this payload is populated by an 
  # external attestation agent (e.g., Keylime) verifying /dev/tpmrm0.
  # Current prototype reads from telemetry payload for testing.
  ```
- In the paper: "The system consumes a structured trust context (TPM attestation state, IMA measurement verdict, SLSA provenance status). Integration with Keylime for real hardware quote verification is left as future work (Section 7)."

---

### 1.5 Standardize System Name *(Minor — 30 minutes)*
`docs/research-and-algorithms.md` and `docs/advanced-differentiators.md` say "AegisGraph". Everything else says "Vajra."

- **Decision**: Use **"Vajra"** as the system name throughout (it's in the repo name, README, and code comments)
- Find & replace "AegisGraph" in all `.md` files under `docs/`

---

**Phase 1 Deliverable**: Codebase where every claim in the paper is backed by code that actually does what it claims.

---

## Phase 2: Real Linux Evaluation Setup
> **Goal**: Run the system on a real Linux host (bare metal or VM) and collect real measurements. This is the most important phase for paper credibility.

### 2.1 Set Up the Testbed
**Minimum requirement**: A Linux VM or spare machine with kernel ≥ 5.15 (BTF support).

**Recommended setup**:
```
OS:         Ubuntu 22.04 LTS or Kali 2024.x
Kernel:     6.x (BTF enabled — verify with: ls /sys/kernel/btf/vmlinux)
CPU:        4 vCPU (or physical cores)
RAM:        8 GB
Tools:      cargo, clang, llvm, libbpf-dev, bpftool, python3.11, uv
Comparison: falco (install via apt), auditd (pre-installed)
```

**Document in paper (Table: Testbed Configuration)**:
```
Component     | Specification
CPU           | Intel/AMD x86_64, N cores @ X GHz
RAM           | Y GB DDR4
OS            | Ubuntu 22.04 LTS
Kernel        | 6.x.x (BTF-enabled)
eBPF Runtime  | libbpf 1.x, bpftool
Python        | 3.11.x (uv venv)
```

---

### 2.2 Verify Real eBPF Probe Loading
```bash
cd bpf && make clean && make
sudo bpftool prog load process_trace.bpf.o /sys/fs/bpf/vajra_probe autoattach
sudo bpftool prog show name observe_process  # Must show it's loaded
```
- **Measure**: Confirm kernel ring buffer events arrive when you run `ls`, `cat /etc/passwd`, etc.
- **Screenshot/log**: Save as evidence for the paper

---

### 2.3 Measure Real Overhead *(replaces synthetic benchmarks)*
Run Vajra with eBPF probes active under a realistic workload (nginx serving requests, python workers, etc.):

```bash
# Measure CPU overhead (compare before vs after eBPF load)
mpstat 1 60  # 60-second sample

# Measure RSS memory
ps aux | grep aegis-agent  # or use /proc/PID/status

# Measure event processing latency
# Add timestamps in agent/src/main.rs:
# kernel_emit_ns → ring_read_ns → python_assess_ns = latency
```

**Paper Table (replace current synthetic benchmarks)**:
| Metric | Baseline (no probe) | Vajra Active | Overhead |
|--------|--------------------|--------------| ---------|
| CPU %  | X.X%               | X.X%         | ΔX%      |
| RSS MB | X MB               | X MB         | ΔX MB    |
| Latency| —                  | X ms (p99)   | —        |
| Ring Drop Rate | —        | 0.00%        | —        |

> [!CAUTION]
> Do NOT copy the synthetic numbers (`1.2% CPU`, `36.4MB`, `4.5ms`) into the paper as real-kernel measurements. Reviewers will ask for the exact testbed and methodology. If you cannot run real eBPF yet, label the existing numbers as "simulation-mode measurements" and state real eBPF overhead measurements are ongoing.

---

## Phase 3: Comparative Experiments & Benchmarks
> **Goal**: Show Vajra detects things competitors miss, with comparable or lower overhead.

### 3.1 Comparison Baselines to Set Up

| System | Install Command | What to Compare |
|--------|----------------|-----------------|
| **auditd** | `sudo apt install auditd` | Detection coverage, false positives, alert explainability |
| **Falco** | `sudo apt install falco` | Same 5 attack scenarios, overhead, alert quality |
| **Plain eBPF (no AI)** | Just raw event count | Show value of Markov + Noisy-OR fusion |

---

### 3.2 Run Attack Scenarios on All 3 Systems
For each of the 5 scenarios (scenarios 01–05 in `test-lab/`):

1. **Reset system state**
2. **Run the same attack script** against all 3 systems simultaneously (or sequentially)
3. **Record**:
   - Did it detect? (True Positive / False Negative)
   - How long to detect? (latency)
   - Was the alert explainable? (Y/N)
   - Overhead during detection?

**Result Table (core contribution of paper)**:
```
Scenario         | Vajra         | Falco    | auditd   | No-AI eBPF
-----------------+---------------+----------+----------+-----------
Normal Web       | ✅ Score 0.00 | ✅ Clean | ✅ Clean | ✅ Clean
/tmp RevShell    | ✅ Score 1.00 | ✅ Alert | ✅ Alert | ⚠️ Raw only
LotL Exfil       | ✅ Score 1.00 | ✅ Alert | ❌ Missed| ⚠️ Raw only
PSI OOM Forecast | ✅ Score 0.99 | ❌ N/A   | ❌ N/A   | ❌ N/A
TPM Attest Fail  | ✅ Frozen     | ❌ N/A   | ❌ N/A   | ❌ N/A
```

---

### 3.3 Measure False Positive Rate *(crucial for any IDS paper)*
Run Vajra on a **benign workload** for at least 30 minutes:
- Start nginx, run a web benchmark (wrk, ab), run database queries, run system updates
- Count: how many events are flagged that shouldn't be?
- **FPR = FP / (FP + TN)** — aim for < 2%
- If FPR is high, tune thresholds and document the tuning process

---

### 3.4 Counterfactual Quality Evaluation
After fixing the solver (Phase 1.1), validate explanation quality:
- For each attack scenario, does the counterfactual correctly identify the minimal change?
- Does $R(e \oplus \delta^*) < 0.20$ after applying the proposed change?
- Human evaluation: is the verbalized explanation actionable and accurate?

---

## Phase 4: Write Related Work & Background
> **Goal**: Academic framing — what exists, what gap you fill.

### 4.1 Papers You Must Cite

**eBPF & Kernel Telemetry**:
- Gregg, B. (2019). *BPF Performance Tools*. Addison-Wesley. (eBPF background)
- Weaver, N. et al. — Falco/eBPF syscall tracing papers
- Cilium/Tetragon documentation (as related system)

**Provenance-Based IDS**:
- Han, X. et al. (2020). *Unicorn: Runtime Provenance-Based Detector for APT*. NDSS 2020.
- Milajerdi, S. M. et al. (2019). *HOLMES: Real-time APT Detection*. IEEE S&P 2019.
- King, S. T., & Chen, P. M. (2003). *Backtracking Intrusions*. SOSP 2003. (foundational)

**Linux PSI / Reliability**:
- Weiner, J. et al. (2020). *Transparent Memory Offloading in Datacenters*. EuroSys 2020. (PSI)
- Facebook Engineering Blog on PSI (cites for /proc/pressure design)

**Counterfactual Explainability (XAI)**:
- Wachter, S., Mittelstadt, B., & Russell, C. (2017). *Counterfactual Explanations Without Opening the Black Box*. Harvard JOLT.
- Mothilal, R. K. et al. (2020). *DICE: Diverse Counterfactual Explanations*. FAccT 2020.
- Guidotti, R. et al. (2018). *A Survey of Methods for Explaining Black Box Models*. ACM CSUR.

**Bayesian Anomaly Fusion**:
- Muñoz-González, L. et al. (2017). *Bayesian Network-Based Intrusion Detection*. (Noisy-OR in security)

**LLM Grounding / Hallucination**:
- Rawte, V. et al. (2023). *A Survey of Hallucination in LLMs*. arXiv 2023.

---

### 4.2 Related Work Section Structure
```
4.1 Kernel Telemetry & eBPF-Based IDS
    - Falco, Tetragon, Sysdig (rule-based eBPF)
    - Gap: no behavioral modeling, no counterfactuals

4.2 Provenance-Based Intrusion Detection
    - Unicorn, HOLMES (graph-based, heavy)
    - Gap: no real-time PSI, no actionable XAI, heavy overhead

4.3 Explainable AI for Security
    - SHAP/LIME applied to IDS (tabular, not graph-based)
    - Gap: no L0-minimal, no grounding guarantees

4.4 Linux Reliability Monitoring
    - PSI, cgroup v2, OOM killer papers
    - Gap: none integrated with security detection

Vajra bridges all four areas in a unified, low-overhead system.
```

---

## Phase 5: Write the Paper
> **Goal**: Full first draft in IEEE/USENIX/ACM two-column format.

### 5.1 Paper Structure (Target: 12–14 pages for conference, 6–8 for workshop)

```
1. Introduction              (~1.5 pages)
   - Problem statement (dual failure of HIDS + black-box ML)
   - Contributions (numbered list, 4-5 bullets)
   - Paper organization

2. Background & Threat Model (~1 page)
   - Linux kernel event model (execve, openat2, tcp_connect)
   - Attacker capabilities (LotL, reverse shell, memory abuse)
   - Defender constraints (low overhead, explainability, sovereignty)

3. System Design            (~2.5 pages)
   3.1 Kernel Telemetry Layer (eBPF CO-RE, Rust agent, PSI)
   3.2 AI Behavioral Core (Markov, PSI EWMA, Noisy-OR)
   3.3 Causal Provenance DAG
   3.4 L₀ Counterfactual Explainability
   3.5 Policy Governance & Reversible Containment
   3.6 Sovereign LLM Assistant with GroundingValidator

4. Mathematical Formulation  (~1.5 pages)
   - Laplace Markov (equations from README, fix weighted Noisy-OR)
   - PSI EWMA + Z-score outlier
   - L₀ counterfactual search algorithm (pseudocode)
   - Grounding validator set-membership check

5. Implementation           (~1 page)
   - eBPF CO-RE probes (hooks, ring buffer)
   - Rust agent (dual-mode)
   - Python services (FastAPI, detector, responder, graph)
   - Tech stack table

6. Evaluation               (~3 pages)  ← most important section
   6.1 Testbed Setup (Table: hardware specs)
   6.2 Detection Accuracy (Table: 5 scenarios vs Falco vs auditd)
   6.3 False Positive Rate (benign workload test)
   6.4 Overhead Benchmarks (Table: real measurements)
   6.5 Counterfactual Quality (case study, verbalized examples)
   6.6 GroundingValidator Effectiveness (LLM hallucination reduction)

7. Discussion & Limitations  (~0.5 page)
   - Real eBPF at scale (Kubernetes DaemonSet — future)
   - Baseline poisoning resistance (shadow baseline — future)
   - TPM hardware integration (future)

8. Related Work              (~1 page)
   (from Phase 4)

9. Conclusion               (~0.3 page)

References                   (15–25 citations)
```

---

### 5.2 Writing Tips Specific to This Paper

**For the Contributions List (Section 1)**:
```
We make the following contributions:
1. Vajra: A unified Linux runtime security system combining eBPF CO-RE 
   kernel telemetry, Laplace-smoothed Markov behavioral modeling, and 
   Linux PSI reliability forecasting in a single Bayesian fusion engine.
2. A greedy L₀-minimal counterfactual explanation engine for provenance 
   DAGs, generating actionable natural-language explanations grounded in 
   verified execution evidence.
3. GroundingValidator: A mechanical set-membership check that eliminates 
   LLM hallucination in security-critical on-premises AI assistants.
4. A reversible policy-governed containment system using cgroup v2 with 
   HMAC-signed audit receipts and automatic 30-minute TTL rollback.
5. A comprehensive evaluation across 5 attack scenarios showing [X]% 
   detection rate with [Y]% fewer false positives than auditd/Falco.
```

**Key things NOT to overclaim**:
- Don't say "eliminates alert fatigue" — say "reduces"
- Don't say "zero-overhead" — say "sub-2.5% CPU overhead"
- Don't say TPM is "fully implemented" — say "abstracted for hardware integration"

---

### 5.3 Formatting Tools

**For IEEE format** (most common at RAID, S&P):
```latex
\documentclass[conference]{IEEEtran}
```

**For USENIX format**:
```latex
% Use the official USENIX LaTeX template from usenix.org
```

**Equation tools** (LaTeX):
```latex
\hat{P}(v \mid u, \mathcal{W}_k) = \frac{C_{\mathcal{W}_k}(u \to v) + \alpha}
    {\sum_{v' \in V} C_{\mathcal{W}_k}(u \to v') + \alpha \cdot |V|}
```

**For diagrams**: Export the Mermaid architecture diagram as SVG, convert to PDF for LaTeX inclusion.

---

## Phase 6: Review & Submit

### 6.1 Internal Review Checklist
- [ ] Every claim in the paper is backed by a measurement or code reference
- [ ] Every equation matches the code implementation
- [ ] Related work cites the 10+ mandatory papers
- [ ] Evaluation section has real (not synthetic) overhead numbers, or clearly labeled synthetic
- [ ] False positive rate is measured and reported
- [ ] Comparison with at least 2 baseline systems (Falco, auditd)
- [ ] Counterfactual solver actually recomputes R and verifies the constraint
- [ ] Limitations section is honest about what isn't done yet
- [ ] No "AegisGraph" remains — consistent "Vajra" throughout
- [ ] Abstract is ≤ 200 words and contains: problem, approach, key result, claim

### 6.2 Venue Decision Tree

```
Are the real eBPF experiments done?
├── YES → Can we show detection accuracy + overhead?
│         ├── YES → Submit to RAID 2026 (full paper, Oct deadline)
│         │         or EuroSec 2027 (workshop, 6 pages)
│         └── NO  → Submit to arXiv first, then revise
└── NO  → 
          ├── Theory + design sound? → Submit to workshop (EuroSec/CSET)
          │   with "prototype evaluation" framing
          └── Needs more time → arXiv preprint → revise → conference
```

### 6.3 Submission Deadlines to Target

| Venue | Type | Typical Deadline | URL |
|-------|------|-----------------|-----|
| **RAID 2026** | Full conference | ~August 2026 (watch CFP) | raid2026.org |
| **EuroSec 2027** | Workshop (EuroSys) | ~February 2027 | eurosec-workshop.github.io |
| **CSET @ USENIX** | Workshop | ~April 2027 | usenix.org/cset |
| **arXiv cs.CR** | Preprint (no peer review) | Any time | arxiv.org |

> [!TIP]
> **Recommended first step**: Upload to arXiv **after Phase 1 is done** (code matches claims). This timestamps your work, gets visibility, and gives you reviewer-style feedback from the community before a formal submission.

---

## Task Assignments (Suggested — Team of 5)

| Team Member | Phase | Specific Tasks |
|------------|-------|---------------|
| **Himanshu (Lead)** | 1, 5 | Fix L₀ solver, write Section 3 (System Design) + Section 4 (Math) |
| **Deepak** | 2, 3 | Linux testbed setup, real eBPF measurement, overhead table |
| **Ayush** | 1, 3 | Add missing eBPF hooks (openat2, tcp_v4_connect), run comparison vs Falco/auditd |
| **Albert** | 4, 5 | Related work survey + write Sections 8 (Related Work) + 1 (Introduction) |
| **Umesh** | 3, 5 | False positive experiments, write Section 6 (Evaluation) |

---

## Timeline

```
Week 1:   Phase 1 — Fix L₀ solver, eBPF hooks, Noisy-OR weights, name consistency
Week 2:   Phase 2 — Testbed setup, verify real eBPF probe loads, measure overhead
Week 3:   Phase 3 — Run all 5 scenarios + Falco + auditd comparison, FPR measurement
Week 4:   Phase 4 — Related work reading + Section 8 draft
Week 5:   Phase 5 — Full paper first draft (all sections)
Week 6:   Phase 5 — Finish draft, fill all tables with real numbers
Week 7:   Phase 6 — Internal review round, fix reviewer simulation feedback
Week 8:   Phase 6 — Final proofread, LaTeX format, arXiv upload / submit to venue
```

---

## Open Questions Before We Start

> [!IMPORTANT]
> Please answer these before execution begins:

1. **Do you have access to a Linux machine/VM** with kernel ≥ 5.15 where you can run actual eBPF probes as root? (This determines if Phase 2 is feasible or needs to be scoped differently)

2. **What is your target deadline?** A conference with a specific deadline changes the priority order.

3. **Short paper (6-8 pages) or full paper (12-14 pages)?** Short paper = skip some evaluation depth, workshop venue. Full paper = full evaluation needed.

4. **Is the Rust agent (`agent/src/main.rs`) functional?** I haven't read that file yet — it affects how much new code is needed for real eBPF sensor integration.
