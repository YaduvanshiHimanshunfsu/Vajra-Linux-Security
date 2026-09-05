# Research Paper Assessment: वज्र (Vajra)

---

## Verdict: **Feasible, but with significant gaps that must be addressed first**

This is not a rejection — the core ideas are legitimate and publishable. But the project in its current form is a **hackathon prototype**, not a research paper. Below is exactly what is strong, what is missing, and what would get it desk-rejected.

---

## ✅ What Is Genuinely Strong (Paper-Worthy)

### 1. The Core Research Idea Is Real and Interesting
The combination of:
- **Laplace-smoothed Markov chain behavioral modeling** for process ancestry anomaly detection
- **Linux PSI forecasting** via online EWMA for pre-crash OOM detection
- **L₀-minimal counterfactual explanations** on provenance DAGs

...is a legitimate, non-trivial systems security contribution. Each component has academic precedent, but their *unification into a single pipeline with grounded explainability and reversible containment* is the novel angle. This is worth publishing in venues like **RAID, NDSS, EuroSec, or USENIX Security (workshop tracks)**.

### 2. Math Is Formalized
The mathematical formulation is real:
- Laplace-smoothed transition probability is correctly stated
- Bayesian Noisy-OR fusion is correctly implemented
- EWMA online variance update is correctly coded in `reliability.py`
- L₀ counterfactual solver has a proper formulation, even if the solver itself is heuristic

### 3. Architecture Is Well-Designed
The layered architecture (eBPF → Behavioral Core → XAI → SOAR → UI) is sound and described coherently across multiple docs. This maps well to a "System Design" section in a paper.

### 4. The GroundingValidator Idea Is Novel
The mechanistic set-membership check to prevent LLM hallucination in a security context ($E_{\text{ref}} \subseteq E_{\text{subgraph}}$) is a concrete, simple, and verifiable safety mechanism. This alone could be a short paper.

### 5. Code Is Clean
The Python code (`engine.py`, `profiles.py`, `counterfactual.py`, `reliability.py`, `assistant.py`) is well-structured, well-documented, and follows proper software engineering. 100% unit test pass rate is credible given the code quality.

---

## ❌ Critical Problems (Would Get Desk-Rejected or Rejected at Review)

### Problem 1: The L₀ Counterfactual Solver Is Not Actually an Optimizer
**This is the most serious issue.**

The paper claims to solve:
$$\delta^* = \arg\min_{\delta \in \Delta} \|\delta\|_0 \quad \text{s.t.} \quad R(e \oplus \delta) < \theta_{\text{benign}}$$

But reading `counterfactual.py`, the actual implementation is a **hardcoded heuristic rule list** — it checks predefined conditions (is path `/tmp`?, is artifact unsigned?, was transition novel?) and appends pre-written deltas. It does **not** search over the space Δ, does not recompute R after perturbation, and does not verify $R(e \oplus \delta^*) < \theta_{\text{benign}}$. 

In a paper, this would be called out immediately in peer review as **claiming formal optimization but implementing a lookup table**. You must either:
- **Option A**: Implement a real greedy L₀ search (iterate features, flip each, recompute R, stop at threshold)
- **Option B**: Reframe it honestly as "a heuristic explanation generator guided by L₀ principles" — less impressive but honest

### Problem 2: Zero Real-World Evaluation
All 5 test scenarios are **synthetic replays** running inside the same Python process using fake data. There is:
- No evaluation on a real Linux system with actual eBPF probes attached
- No comparison against baseline tools (auditd, Falco, Sysdig) on real data
- No false positive rate measurement on real production workloads
- No measurement of actual eBPF overhead in a real kernel (the `< 2.5% CPU` claim is presented as a benchmark but is measured on synthetic event replay, not real kernel instrumentation)

A paper **must** have a real evaluation section. Without this, reviewers will reject it as an unvalidated prototype.

### Problem 3: The TPM/IMA Hardware Attestation Is Simulated
`TrustContext` in the code only reads fields from the JSON payload — there is no actual TPM PCR quote verification, no real IMA measurement list comparison, no `/dev/tpmrm0` interaction. This is fine for a hackathon. But the paper cannot claim "Hardware TPM 2.0 Attestation" as a completed feature — it must be described as a **trust context abstraction layer** with a note that real TPM integration is future work.

### Problem 4: Benchmarks Are Not Reproducible
The performance table states:
- CPU Overhead: `1.2% - 1.8%`
- RAM: `36.4 MB`
- Latency: `4.5 ms`

But these appear to come from synthetic replay mode, not real eBPF kernel probes. A reviewer will ask: "What machine? What kernel version? What workload? What was the measurement methodology?" These numbers need to be reproducible with a documented testbed.

### Problem 5: No Literature Review / Related Work
There is no `related_work.md` or equivalent. For a paper you need to properly cite and position against:
- **Falco** (eBPF-based behavioral detection, CNCF project)
- **Tetragon** (Cilium/eBPF runtime security)
- **PROVENANCE-based IDS** (Han et al., USENIX Security 2020 — Unicorn)
- **Counterfactual XAI literature** (Wachter et al., 2017; Mothilal et al., 2020)
- **PSI/reliability literature** (Facebook's PSI paper by Weiner et al., 2020)
- **Noisy-OR Bayesian networks** in security (established literature)

Without this, the paper has no academic framing.

### Problem 6: The eBPF Code Is Minimal (Only 1 Hook)
`process_trace.bpf.c` has exactly **one hook**: `sched_process_exec`. The claimed hooks for `vfs_write`, `openat2`, and `tcp_v4_connect` exist in the documentation and architecture diagram but **are not in the actual BPF C code**. The Rust agent (`agent/src/main.rs` — not read yet but implied by the repo structure) may handle replay but not real kernel-level VFS or network hooks. This gap is critical — if a reviewer checks the code against the claims, it will fail.

---

## ⚠️ Moderate Issues (Need Fixing, Won't Kill the Paper)

### 1. Naming Inconsistency
- The docs call it "AegisGraph" in several places (`docs/research-and-algorithms.md`, `docs/advanced-differentiators.md`)
- The main repo calls it "Vajra (वज्र)"
- A paper cannot have two system names. Pick one and be consistent everywhere.

### 2. `pitch.md` and `pptx_help.md` Are Presentation Files
These exist in the root of a repository that should be paper-ready. They don't hurt the code, but clean up the repo before any academic submission.

### 3. The Noisy-OR Fusion Weights Are All Equal
The code does `1.0 - prod(1.0 - s_i)` but `docs/research-and-algorithms.md` specifies **weighted** Noisy-OR: `R = 1 - ∏(1 - wᵢ·sᵢ)`. There's a discrepancy between the paper's math and the actual code. For a paper this must be consistent.

### 4. LLM Assistant Is Optional But Marketed as Core
Ollama is optional and falls back to a deterministic rule-based response engine. For a paper, this is fine — just describe it honestly as "an optional on-premises LLM layer with a deterministic fallback."

---

## 📋 What You Actually Need to Do to Make It a Paper

| Task | Priority | Effort |
|------|----------|--------|
| Fix counterfactual solver to actually recompute R (or reframe claim) | 🔴 Critical | Medium |
| Add real Linux evaluation with actual eBPF (even on a VM) | 🔴 Critical | High |
| Write a proper Related Work section with 10-15 citations | 🔴 Critical | Medium |
| Add missing eBPF hooks (vfs_write, openat2, tcp_v4_connect) or remove claims | 🔴 Critical | High |
| Fix the TPM/IMA framing — call it a "trust abstraction" not full attestation | 🟡 Important | Low |
| Fix weighted vs unweighted Noisy-OR discrepancy | 🟡 Important | Low |
| Document testbed specs for benchmark reproduction | 🟡 Important | Low |
| Standardize system name (Vajra vs AegisGraph) | 🟢 Minor | Trivial |
| Compare against Falco/Tetragon/auditd on same workload | 🔴 Critical | High |
| False positive/negative rate measurement on benign workloads | 🔴 Critical | High |

---

## 🎯 Recommended Venue Targets (Realistic, Not Aspirational)

If you fix the critical issues above:

| Venue | Type | Fit |
|-------|------|-----|
| **RAID 2026** | Research conference | Strong fit (runtime detection, systems) |
| **EuroSec (EuroSys workshop)** | Workshop paper (4-6 pages) | Good fit for system prototype |
| **CSET @ USENIX** | Workshop | Good fit for security tooling |
| **IEEE S&P (SaTML/LLM-sec workshops)** | Workshop | For the GroundingValidator component |
| **arXiv** | Preprint only | Good for immediate visibility while you run real experiments |

> [!CAUTION]
> Do NOT submit to USENIX Security, IEEE S&P, CCS, or NDSS main track in current state. The evaluation gap alone will cause rejection.

---

## Summary in Plain Language

**The idea is real and worth publishing.** The math is mostly correct. The code is clean. The architecture is well-thought-out.

**But:** You are claiming things the code does not yet fully do (real eBPF hooks for VFS/network, real TPM attestation, a real L₀ optimizer). And you have no comparison against real tools on real systems. For a hackathon, that's fine. For a paper, that's a rejection.

The path from here to a publishable paper is about **4-8 weeks of focused work** — primarily running the system on a real Linux VM, adding the missing eBPF hooks, doing honest comparative evaluation, and writing the related work section.
