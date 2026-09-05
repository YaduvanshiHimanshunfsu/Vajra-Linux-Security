# Development order

1. Produce valid, versioned events before building any ML model.
2. Implement high-precision rules and explainable statistical baselines.
3. Build provenance edges and alert investigation views.
4. Add sequence and temporal graph models only after benign telemetry is available.
5. Operate response in recommendation mode before enabling any automatic policy.

## Baseline promotion

New events enter a candidate baseline. A candidate can only become active after a
verified deployment/change window or analyst approval. This reduces false positives
and prevents training-data poisoning by a persistent attacker.
