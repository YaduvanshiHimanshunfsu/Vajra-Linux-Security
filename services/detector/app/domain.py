"""Unified, dependency-light domain models for the AegisGraph platform."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class Subject:
    process_id: str
    executable: str
    uid: int
    pid: int = 0
    ppid: int = 0


@dataclass(frozen=True)
class Workload:
    workload_id: str
    environment: str = "unknown"


@dataclass(frozen=True)
class TrustContext:
    """Structured hardware and supply-chain trust abstraction layer.

    In production deployments, this payload is populated by an external attestation
    agent (such as Keylime v2 verifier) that cryptographically verifies TPM 2.0 PCR quotes
    against /dev/tpmrm0 and validates IMA runtime measurement lists against signed policy.
    In the evaluation testbed and prototype, structured trust states (verified, failed, unavailable)
    are consumed from telemetry payloads to evaluate trust-gating branches deterministically.
    """
    host_attestation: str = "unavailable"
    agent_integrity: str = "unavailable"
    artifact_verification: str = "unavailable"
    runtime_binary_sha256: str | None = None
    artifact_signer_identity: str | None = None
    sbom_reference: str | None = None
    slsa_provenance_reference: str | None = None



@dataclass(frozen=True)
class Event:
    event_id: str
    observed_at: str
    host_id: str
    boot_id: str
    event_type: str
    subject: Subject
    object_type: str
    object_value: str
    workload: Workload
    result: str
    attributes: dict[str, str] = field(default_factory=dict)
    sensor_confidence: float = 1.0
    trust: TrustContext = field(default_factory=TrustContext)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Event":
        subject = data["subject"]
        workload = data["workload"]
        return cls(
            event_id=str(data.get("event_id", "evt-auto")),
            observed_at=str(data.get("observed_at", "")),
            host_id=str(data.get("host_id", "host-default")),
            boot_id=str(data.get("boot_id", "boot-default")),
            event_type=str(data["event_type"]),
            subject=Subject(
                process_id=str(subject["process_id"]),
                executable=str(subject["executable"]),
                uid=int(subject.get("uid", 1000)),
                pid=int(subject.get("pid", 0)),
                ppid=int(subject.get("ppid", 0)),
            ),
            object_type=str(data["object_type"]),
            object_value=str(data["object_value"]),
            workload=Workload(
                workload_id=str(workload["workload_id"]),
                environment=str(workload.get("environment", "unknown")),
            ),
            result=str(data.get("result", "success")),
            attributes={str(key): str(value) for key, value in data.get("attributes", {}).items()},
            sensor_confidence=float(data.get("sensor_confidence", 1.0)),
            trust=TrustContext(**data.get("trust", {})),
        )


@dataclass(frozen=True)
class Finding:
    detector: str
    finding_id: str
    score: float
    severity: str
    evidence: list[str]
    recommended_action: str
    mitre_techniques: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Assessment:
    event_id: str
    security_score: float
    reliability_score: float
    telemetry_trust_score: float
    automation_allowed: bool
    baseline_updated: bool
    findings: list[Finding]
    counterfactual: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "security_score": self.security_score,
            "reliability_score": self.reliability_score,
            "telemetry_trust_score": self.telemetry_trust_score,
            "automation_allowed": self.automation_allowed,
            "baseline_updated": self.baseline_updated,
            "findings": [finding.to_dict() for finding in self.findings],
            "counterfactual": self.counterfactual,
        }
