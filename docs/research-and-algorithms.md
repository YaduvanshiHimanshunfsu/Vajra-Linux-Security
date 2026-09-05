# Vajra (वज्र) AI & Anomaly Detection: Mathematical Formulation and Research

This document details the mathematical algorithms, statistical foundations, and AI models powering the **Vajra (वज्र) Explainable Linux Security & Reliability Assistant**.

---

## 1. Problem Formalization & Threat Model

A Linux host emits a discrete temporal event stream $\mathcal{S} = \{e_1, e_2, \dots, e_t\}$.
Each event $e_i$ is a tuple:
$$e_i = \langle \tau_i, \mathcal{W}_i, \mathcal{P}_i, \text{type}_i, \mathcal{O}_i, \mathcal{T}_i, \mathcal{A}_i \rangle$$
where:
- $\tau_i$: Nanosecond timestamp ($t_{\text{mono}}$).
- $\mathcal{W}_i$: Workload identity ($\text{host\_id} \oplus \text{systemd\_unit} \oplus \text{image\_digest}$).
- $\mathcal{P}_i$: Process identity ($\text{boot\_id} \oplus \text{PID} \oplus t_{\text{start}}$).
- $\text{type}_i \in \{\text{PROCESS\_EXEC}, \text{PROCESS\_EXIT}, \text{FILE\_ACCESS}, \text{NETWORK\_CONNECT}, \text{RESOURCE\_PRESSURE}, \text{PRIVILEGE\_CHANGE}\}$.
- $\mathcal{O}_i$: Target object (executable path, file path, socket $\text{IP:port}$, cgroup).
- $\mathcal{T}_i$: Hardware and supply-chain trust context ($\text{TPM}, \text{IMA}, \text{SLSA}$).
- $\mathcal{A}_i$: Contextual attribute map.

The system must solve three concurrent problems in real time:
1. **Intrusion Detection**: Estimate $P(\text{Intrusion} \mid e_t, \mathcal{S}_{<t}, \mathcal{W}_k)$.
2. **Reliability & Failure Forecasting**: Estimate $P(\text{System Failure in } \Delta t \mid \mathcal{S}_{\le t})$.
3. **Explainability & Minimal Counterfactuals**: Find minimal feature delta $\delta^*$ explaining why $e_t$ is anomalous.

---

## 2. Behavioral Normality Learning Algorithms

### 2.1 Higher-Order Markov Process Ancestry Model
Workloads exhibit deterministic or near-deterministic process spawning hierarchies.
Let $u = \text{parent executable}$ and $v = \text{child executable}$.
For workload $\mathcal{W}_k$, we model transitions as a directed probabilistic state graph $G_k = (V, E, W)$.

The transition probability with **Laplace (additive) smoothing** is:
$$\hat{P}(v \mid u, \mathcal{W}_k) = \frac{C_{\mathcal{W}_k}(u \to v) + \alpha}{\sum_{v' \in V} C_{\mathcal{W}_k}(u \to v') + \alpha \cdot |V|}$$
where:
- $C_{\mathcal{W}_k}(u \to v)$: Observed count of transition $u \to v$ in verified baseline.
- $\alpha$: Smoothing parameter ($\alpha = 0.1$).
- $|V|$: Known executable vocabulary size for workload $\mathcal{W}_k$.

The **Surprisal (Self-Information)** anomaly score is:
$$I(u \to v) = -\log_2 \hat{P}(v \mid u, \mathcal{W}_k)$$
Normalized transition novelty $S_{\text{exec}} \in [0.0, 1.0]$:
$$S_{\text{exec}} = \min\left(1.0, \frac{I(u \to v)}{I_{\text{max}}}\right)$$
where $I_{\text{max}} = -\log_2 \left(\frac{\alpha}{\alpha \cdot (|V| + 1)}\right)$.

---

### 2.2 Network Egress Entropy & Rarity Model
For network connection events $e = \text{NETWORK\_CONNECT}$, destination objects $d = \langle \text{IP}, \text{Port}, \text{Proto} \rangle$ are evaluated against the workload's empirical distribution.

Empirical probability of destination $d$:
$$\hat{P}(d \mid \mathcal{W}_k) = \frac{C_{\mathcal{W}_k}(d) + \beta}{N_{\mathcal{W}_k}^{\text{net}} + \beta \cdot |D|}$$
If destination $d$ is external (public IP not in RFC 1918 / internal CIDR):
$$S_{\text{net}} = \begin{cases}
1.0 - \hat{P}(d \mid \mathcal{W}_k) & \text{if external destination} \\
0.5 \cdot (1.0 - \hat{P}(d \mid \mathcal{W}_k)) & \text{if internal cluster destination}
\end{cases}$$

---

### 2.3 System Reliability & Pressure Stall Forecasting (PSI)
Linux Pressure Stall Information (PSI) records the percentage of time tasks are delayed due to resource starvation (Memory, CPU, I/O) over 10s, 60s, and 300s windows.

Let the multivariate resource pressure vector at time $t$ be:
$$\mathbf{x}_t = \begin{bmatrix} \text{some}_{10s} \\ \text{full}_{10s} \\ \Delta \text{some} / \Delta t \\ \text{PSI}_{\text{mem}} \\ \text{PSI}_{\text{io}} \end{bmatrix}$$

We compute dynamic exponential moving average (EWMA) and variance:
$$\mu_t = \lambda \mathbf{x}_t + (1 - \lambda) \mu_{t-1}$$
$$\sigma_t^2 = \lambda (\mathbf{x}_t - \mu_t)^2 + (1 - \lambda) \sigma_{t-1}^2$$

The **Reliability Risk Score** $R_{\text{rel}} \in [0.0, 1.0]$ is computed via the cumulative distribution function (CDF) of the Mahalanobis distance / robust Z-score:
$$z_t = \max_{j} \left( \frac{x_{t,j} - \mu_{t,j}}{\sigma_{t,j} + \epsilon} \right)$$
$$R_{\text{rel}} = \frac{2}{1 + e^{-k (z_t - z_{\text{threshold}})}}$$

---

## 3. Calibrated Risk Fusion (Bayesian Noisy-OR Model)

Individual detectors produce independent evidence scores $s_i \in [0.0, 1.0]$ with reliability weights $w_i \in [0.0, 1.0]$.
Under the Noisy-OR assumption (the presence of any single high-confidence attack vector is sufficient to warrant alert), the fused score is:
$$R_{\text{fused}} = 1.0 - \prod_{i=1}^M (1.0 - s_i) \quad \text{(uniform weight, } w_i = 1.0\text{)}$$

**Telemetry Trust Penalty**:
If TPM host attestation or agent binary integrity is unverified or compromised:
$$T_{\text{trust}} = \begin{cases}
1.0 & \text{if host\_attestation = verified and agent\_integrity = verified} \\
0.70 & \text{if host\_attestation = unavailable (unattested VM)} \\
0.0 & \text{if host\_attestation = failed or agent\_integrity = failed}
\end{cases}$$
When $T_{\text{trust}} < 0.90$, **automated remediation is strictly locked**, and baseline learning is frozen.

---

## 4. Counterfactual Explainability Algorithm

An alert must explain not just *why* an anomaly was detected, but the **minimal set of condition changes** that would flip the model verdict to benign ($R < \theta$).

Given event $e$ with feature set $\mathcal{F} = \{f_1, f_2, \dots, f_m\}$, we formulate the counterfactual search as:
$$\delta^* = \arg\min_{\delta \in \Delta} \|\delta\|_0 \quad \text{s.t.} \quad R(e \oplus \delta) < \theta_{\text{benign}}$$
where:
- $\|\delta\|_0$ is the $L_0$ sparsity norm (number of modified facts).
- $\Delta$ is the set of valid attribute perturbations (e.g., changing binary signature status, changing destination IP to approved CIDR, changing execution path from `/tmp` to `/usr/bin`).

**Generated Explanation Output**:
```json
{
  "finding_id": "AG-BEH-EXEC-NOVELTY",
  "verdict": "CRITICAL_THREAT",
  "current_score": 0.94,
  "counterfactual": {
    "target_score": 0.12,
    "minimal_changes_required": [
      {
        "feature": "trust.artifact_verification",
        "current_value": "failed",
        "required_value": "verified",
        "delta_impact": -0.45
      },
      {
        "feature": "subject.executable",
        "current_value": "/tmp/kworker_rev",
        "required_value": "approved_workload_binary",
        "delta_impact": -0.37
      }
    ],
    "explanation_text": "Risk would drop from 0.94 (Critical) to 0.12 (Low) if the binary had a verified SLSA provenance signature AND was executed from a standard binary path instead of /tmp."
  }
}
```
