# Architecture

```text
Linux sensor -> event broker -> validator/enricher -> detectors -> API/UI
                                      |                 |
                                      v                 v
                               ClickHouse          provenance graph
                                      |                 |
                                      +---- response policy engine
```

## Trust boundaries

- The Linux agent is privileged and communicates through mutual TLS in production.
- The broker and database are not trusted to authorize containment.
- Models supply scores and evidence only; they never run commands.
- The response service verifies a signed policy, validates scope, records an audit
  receipt, and attaches expiry/rollback information before any action.

## Workload identity

A behavioural profile is keyed by a stable `workload_id`:

```text
host role + systemd unit OR container image digest + deployment identity
```

PID alone is never an identity because PIDs are reused. Process identity is composed
from host, boot ID, PID, and process start time.
