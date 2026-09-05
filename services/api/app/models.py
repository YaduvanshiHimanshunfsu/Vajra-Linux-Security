from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class EventType(StrEnum):
    PROCESS_EXEC = "PROCESS_EXEC"
    PROCESS_EXIT = "PROCESS_EXIT"
    FILE_ACCESS = "FILE_ACCESS"
    NETWORK_CONNECT = "NETWORK_CONNECT"
    PRIVILEGE_CHANGE = "PRIVILEGE_CHANGE"
    INTEGRITY_CHANGE = "INTEGRITY_CHANGE"
    RESOURCE_PRESSURE = "RESOURCE_PRESSURE"
    SERVICE_STATE = "SERVICE_STATE"


class VerificationState(StrEnum):
    VERIFIED = "verified"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"
    PENDING = "pending"


class ProcessIdentity(BaseModel):
    """Stable identity: host boot ID + PID + process start time form process_id."""

    model_config = ConfigDict(extra="ignore")

    process_id: str = Field(min_length=1, max_length=256)
    pid: int = Field(ge=1)
    ppid: int = Field(default=0, ge=0)
    executable: str = Field(min_length=1, max_length=4096)
    command_line_hash: str | None = Field(default=None, max_length=128)
    uid: int = Field(default=1000, ge=0)
    capabilities: list[str] = Field(default_factory=list)


class WorkloadIdentity(BaseModel):
    model_config = ConfigDict(extra="ignore")

    workload_id: str = Field(min_length=1, max_length=256)
    systemd_unit: str | None = None
    container_id: str | None = None
    image_digest: str | None = None
    cgroup: str | None = None
    environment: str = "unknown"


class TrustContext(BaseModel):
    model_config = ConfigDict(extra="ignore")

    host_attestation: VerificationState = VerificationState.UNAVAILABLE
    agent_integrity: VerificationState = VerificationState.UNAVAILABLE
    artifact_verification: VerificationState = VerificationState.UNAVAILABLE
    runtime_binary_sha256: str | None = Field(default=None, max_length=128)
    artifact_signer_identity: str | None = Field(default=None, max_length=512)
    sbom_reference: str | None = Field(default=None, max_length=2048)
    slsa_provenance_reference: str | None = Field(default=None, max_length=2048)


class LineageContext(BaseModel):
    model_config = ConfigDict(extra="ignore")

    causal_trace_id: str | None = Field(default=None, max_length=256)
    parent_event_id: str | None = None
    graph_partition_id: str | None = Field(default=None, max_length=256)


class SecurityEvent(BaseModel):
    model_config = ConfigDict(extra="ignore")

    schema_version: str = "1.0"
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    observed_at: datetime | str
    host_id: str = Field(default="demo-host", min_length=1, max_length=256)
    boot_id: str = Field(default="boot-default", min_length=1, max_length=256)
    event_type: EventType | str
    subject: ProcessIdentity
    object_type: str = Field(min_length=1, max_length=64)
    object_value: str = Field(min_length=1, max_length=4096)
    workload: WorkloadIdentity
    result: str = Field(default="success")
    attributes: dict[str, str] = Field(default_factory=dict)
    sensor_confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    trust: TrustContext = Field(default_factory=TrustContext)
    lineage: LineageContext = Field(default_factory=LineageContext)


class Finding(BaseModel):
    model_config = ConfigDict(extra="ignore")

    detector: str
    finding_id: str
    score: float = Field(ge=0.0, le=1.0)
    severity: str
    evidence: list[str]
    mitre_techniques: list[str] = Field(default_factory=list)
    recommended_action: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class EventAssessment(BaseModel):
    event_id: str
    findings: list[Finding]
    security_score: float = Field(ge=0.0, le=1.0)
    reliability_score: float = Field(ge=0.0, le=1.0)
    telemetry_trust_score: float = Field(ge=0.0, le=1.0)
    automation_allowed: bool
    baseline_updated: bool = False
    counterfactual: dict[str, Any] | None = None


class ChatRequest(BaseModel):
    query: str
    event_id: str | None = None


class ChatResponse(BaseModel):
    reply: str
    context_incident_id: str | None = None


class ActionRequest(BaseModel):
    action_type: str  # "FREEZE_CGROUP", "BLOCK_EGRESS", "TERMINATE_PROCESS", "QUARANTINE_CONTAINER"
    target: str
    incident_id: str | None = None
    analyst_approved: bool = True


class ActionResponse(BaseModel):
    success: bool
    message: str
    receipt: dict[str, Any] | None = None
