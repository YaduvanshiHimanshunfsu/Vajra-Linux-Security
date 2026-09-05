# Vajra (वज्र) ATLAS: advanced differentiators

ATLAS means **Attested Temporal Lineage and Adaptive Security**. It is the layer
that makes Vajra (वज्र) more than an eBPF event collector with an AI dashboard.

## 1. Attested runtime-to-supply-chain lineage

For every high-value process execution, link four independent facts:

```text
workload identity -> deployed image/package digest -> signed build provenance
                  -> runtime binary IMA hash -> TPM-backed host attestation
```

The platform should distinguish these cases:

| Situation | Interpretation | Risk behaviour |
|---|---|---|
| Signed artifact, attested host, normal execution | Expected trusted workload | Learn only after approval |
| Signed artifact, attested host, anomalous execution | Possible exploit/living-off-the-land | High behavioural investigation |
| Unsigned/unknown binary, attested host | Supply-chain or execution risk | High security alert |
| Any event from an attestation-failed host | Sensor/kernel trust cannot be assumed | Freeze learning and contain manually |

This prevents the common mistake of treating host telemetry as inherently truthful.
Keylime is the reference integration for TPM-backed boot and IMA runtime attestation;
it supplies verifier/registrar/agent components and can validate IMA measurements
against hashes or signatures.

## 2. Three-view temporal provenance graph

Maintain three correlated graph views rather than one event graph:

1. **Execution view:** process, file, socket, and privilege edges.
2. **Trust view:** image digest, SBOM, signer, SLSA provenance, IMA hash, attestation.
3. **Service view:** OpenTelemetry trace, systemd unit/pod, business endpoint, PSI health.

An alert gains confidence only when its evidence is consistent across independent
views. A process that reads a secret and creates outbound network flow is suspicious;
it becomes critical if its binary is unverified or its host is no longer attested.

Use task-based subgraph segmentation: retain the changing process-centred subgraph,
summarise stable history, and archive raw events in ClickHouse. This controls memory
growth while retaining an investigation path.

## 3. Counterfactual explanation contract

Every severe alert must answer not only “why?” but “what smallest fact would change
the decision?” Examples:

```text
Risk would fall from critical to medium if the destination matched the approved
payments-service identity AND the accessed file was not a secret-labelled object.
```

Generate counterfactuals by removing or replacing a minimum set of anomalous graph
edges, then re-scoring the graph. Store the selected edges, score difference, and
model version. Do not let an LLM invent this explanation; it may only verbalise the
stored result.

## 4. Adversarially robust learning

An attacker can try to hide a path by adding benign-looking graph edges, inducing
event loss, or slowly poisoning a baseline. Defend with:

- frozen approved baseline and shadow candidate baseline;
- dual scoring from raw event and summarised graph views;
- graph-consistency checks across execution, trust, and service views;
- data-quality score from agent heartbeat, event drops, and attestation state;
- no automatic containment when telemetry trust is below threshold;
- signed analyst feedback for promotion/demotion of baseline behaviour.

The future graph model should use logic-preserving contrastive training: benign
representation changes should be invariant, while contradictory cross-view evidence
should remain detectable.

## 5. Shadow-to-enforcement policy synthesis

Learn candidate least-privilege policies from analyst-approved behaviour:

```text
approved process tree + allowed file classes + workload identities + egress peers
                                      -> candidate policy
```

Before enforcement, replay the previous 7–30 days of events in a policy simulator.
Show expected block count, affected workload, policy coverage, and rollback plan.
Only then emit a signed, scoped policy for BPF LSM/Cilium/Tetragon enforcement.
The system therefore evolves from detection to explainable least privilege without
blindly generating a live deny-list.

## 6. Deception as high-confidence evidence

Deploy non-production decoy credential files and canary documents under controlled
paths. Their access is nearly always suspicious and converts uncertain anomaly scores
into strong evidence. Decoys must contain no usable credential, must be clearly
isolated from production secrets, and must not call out to an external tracking URL.

## Delivery priority

1. Implement trust context, baseline freeze, and attestation-failure alerts now.
2. Add image/SBOM/SLSA provenance enrichment and IMA hash lookup next.
3. Build graph segmentation and a cross-view consistency scorer.
4. Add counterfactual explanations and policy replay simulation.
5. Add a temporal GNN and contrastive robustness training only after sufficient
   validated normal telemetry exists.
