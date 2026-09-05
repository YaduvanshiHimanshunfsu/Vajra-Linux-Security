# Event contracts

`aegis_event.proto` is the canonical event format. Producers must populate
`schema_version`, a collision-resistant `event_id`, and a stable process/workload
identity. Consumers must tolerate additive schema changes and reject unknown major
versions.

`trust` and `lineage` are optional additive fields. They bind an event to runtime
attestation, artifact/SBOM provenance, and its causal graph partition. Consumers
must treat an unavailable trust context as lower confidence—not as proof of failure.

The JSON model in `services/api/app/models.py` mirrors this initial contract while
the project is being scaffolded. Protobuf generation and schema-registry validation
will be added before agent-to-broker integration.
