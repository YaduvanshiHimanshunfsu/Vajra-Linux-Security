from __future__ import annotations

import json
import os
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

# Set up module resolution for internal services
ROOT_DIR = Path(__file__).resolve().parents[3]
SERVICES_DIR = ROOT_DIR / "services"

for service_path in [
    SERVICES_DIR / "detector",
    SERVICES_DIR / "graph",
    SERVICES_DIR / "responder",
    ROOT_DIR,
]:
    if str(service_path) not in sys.path:
        sys.path.insert(0, str(service_path))

# Service Imports
from services.detector.app.counterfactual import CounterfactualExplainer
from services.detector.app.domain import Event as DetectorEvent
from services.detector.app.engine import DetectionEngine
from services.detector.app.profiles import ProfileStore
from services.detector.app.reliability import ReliabilityDetector
from services.detector.app.rules import RuleEngine
from services.graph.app.exporter import GraphExporter
from services.graph.app.lineage import ProvenanceGraph
from services.responder.app.executor import RemediationExecutor
from services.responder.app.policy_checker import ResponsePolicyEngine
from services.responder.app.rollback import RollbackScheduler

from .assistant import SecurityAssistant
from .metrics import TelemetryMetricsTracker
from .mitre_navigator import MitreNavigatorExporter
from .models import (
    ActionRequest,
    ActionResponse,
    ChatRequest,
    ChatResponse,
    EventAssessment,
    Finding,
    SecurityEvent,
)

# App Initialization
app = FastAPI(
    title="वज्र (Vajra) AI Linux Security & Reliability Assistant",
    version="1.0.0",
    description="Team_Red_Eagle | Explainable Linux runtime-security and proactive reliability assistant.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Platform Singletons
rule_engine = RuleEngine.from_directory(ROOT_DIR / "policy" / "detection")
profile_store = ProfileStore(minimum_observations=3)
reliability_detector = ReliabilityDetector()
explainer = CounterfactualExplainer()
detection_engine = DetectionEngine(rule_engine, profile_store, reliability_detector, explainer)

provenance_graph = ProvenanceGraph()
policy_engine = ResponsePolicyEngine.from_file(ROOT_DIR / "policy" / "response" / "response_policy.yaml")
executor = RemediationExecutor()
rollback_scheduler = RollbackScheduler()
assistant = SecurityAssistant()
metrics_tracker = TelemetryMetricsTracker()

_incidents_lock = threading.Lock()
recent_incidents: deque[dict[str, Any]] = deque(maxlen=200)


@app.get("/healthz", tags=["platform"])
def healthcheck() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "vajra-api-assistant",
        "team": "Team_Red_Eagle",
        "version": "1.0.0",
    }


@app.post("/v1/events/assess", response_model=EventAssessment, status_code=status.HTTP_200_OK)
def assess_event(event: SecurityEvent) -> EventAssessment:
    """Ingest and assess a security or reliability event using the AI Detection Engine."""
    start_t = time.perf_counter()
    event_dict = event.model_dump()

    # Format datetime if present
    if isinstance(event_dict.get("observed_at"), datetime):
        event_dict["observed_at"] = event_dict["observed_at"].isoformat()
    elif not event_dict.get("observed_at"):
        event_dict["observed_at"] = datetime.now(timezone.utc).isoformat()

    # Convert event_type enum to string value
    if hasattr(event.event_type, "value"):
        event_dict["event_type"] = event.event_type.value

    if "trust" in event_dict and isinstance(event_dict["trust"], dict):
        for k in ["host_attestation", "agent_integrity", "artifact_verification"]:
            val = event_dict["trust"].get(k)
            if hasattr(val, "value"):
                event_dict["trust"][k] = val.value

    # 1. Run Detection Engine
    domain_event = DetectorEvent.from_dict(event_dict)
    assessment = detection_engine.assess(domain_event)

    # 2. Update Provenance Graph
    max_risk = max(assessment.security_score, assessment.reliability_score)
    provenance_graph.ingest_event(event_dict, risk_score=max_risk)

    # 3. Store in Recent Incidents if anomalous or notable
    assessment_dict = assessment.to_dict()
    record = {
        "event_id": assessment.event_id,
        "event": event_dict,
        "findings": assessment_dict["findings"],
        "security_score": assessment.security_score,
        "reliability_score": assessment.reliability_score,
        "telemetry_trust_score": assessment.telemetry_trust_score,
        "automation_allowed": assessment.automation_allowed,
        "counterfactual": assessment.counterfactual,
        "timestamp": event_dict["observed_at"],
    }
    with _incidents_lock:
        recent_incidents.append(record)

    # 4. Check policy for autonomous containment
    if assessment.automation_allowed:
        for finding in assessment.findings:
            if finding.finding_id == "AG-RULE-002":
                receipt = executor.block_egress(event.object_value, ttl_minutes=30)
                rollback_scheduler.schedule(receipt)
            elif finding.finding_id == "AG-REL-PRESSURE-FORECAST" and assessment.reliability_score >= 0.85:
                cgroup_target = event_dict.get("attributes", {}).get("cgroup", event.workload.workload_id)
                receipt = executor.freeze_cgroup(cgroup_target, ttl_minutes=15)
                rollback_scheduler.schedule(receipt)

    # Record telemetry latency
    latency_ms = round((time.perf_counter() - start_t) * 1000, 2)
    metrics_tracker.record_event_latency(latency_ms)

    return EventAssessment(
        event_id=str(assessment.event_id),
        findings=[Finding(**f.to_dict()) for f in assessment.findings],
        security_score=assessment.security_score,
        reliability_score=assessment.reliability_score,
        telemetry_trust_score=assessment.telemetry_trust_score,
        automation_allowed=assessment.automation_allowed,
        baseline_updated=assessment.baseline_updated,
        counterfactual=assessment.counterfactual,
    )


@app.get("/v1/incidents", tags=["incidents"])
def list_incidents(limit: int = 50) -> list[dict[str, Any]]:
    """Retrieve recent flagged security threats and reliability anomalies."""
    with _incidents_lock:
        return list(recent_incidents)[-limit:]


@app.get("/v1/graph", tags=["provenance"])
def get_provenance_graph() -> dict[str, Any]:
    """Retrieve current causal execution graph for Cytoscape visualization."""
    return GraphExporter.to_cytoscape_json(provenance_graph)


@app.get("/v1/mitre/navigator", tags=["mitre"])
def get_mitre_navigator_layer() -> dict[str, Any]:
    """Export detected runtime attack techniques as a standard MITRE ATT&CK Navigator Layer v4 JSON."""
    with _incidents_lock:
        incidents_snapshot = list(recent_incidents)
    return MitreNavigatorExporter.generate_layer(incidents_snapshot)


@app.get("/v1/metrics/overhead", tags=["platform"])
def get_system_overhead_metrics() -> dict[str, Any]:
    """Retrieve real-time telemetry agent CPU %, memory RSS, processing latency, and drop rate."""
    workload_count = len(profile_store._profiles) or 1
    return metrics_tracker.get_metrics(active_workload_count=workload_count)


@app.post("/v1/assistant/chat", response_model=ChatResponse, tags=["assistant"])
def assistant_chat(request: ChatRequest) -> ChatResponse:
    """Interactive natural language security assistant for incident explanation and remediation advice."""
    graph_data = GraphExporter.to_cytoscape_json(provenance_graph)
    with _incidents_lock:
        incidents_snapshot = list(recent_incidents)
        last_id = incidents_snapshot[-1]["event_id"] if incidents_snapshot else None
    reply = assistant.chat_query(
        query=request.query,
        recent_incidents=incidents_snapshot,
        graph_data=graph_data,
    )
    return ChatResponse(reply=reply, context_incident_id=last_id)


@app.post("/v1/actions/execute", response_model=ActionResponse, tags=["remediation"])
def execute_containment_action(request: ActionRequest) -> ActionResponse:
    """Execute a policy-authorized containment action with audit logging."""
    action_type = request.action_type.upper()
    target = request.target

    # ── Policy Authorization Gate ──────────────────────────────────────────
    policy_action_map = {
        "FREEZE_CGROUP": "freeze_cgroup",
        "BLOCK_EGRESS": "temporary_egress_block",
        "TERMINATE_PROCESS": "terminate_process",
        "QUARANTINE_CONTAINER": "quarantine_container",
    }
    policy_action_name = policy_action_map.get(action_type)
    if not policy_action_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown action type '{action_type}'.",
        )

    # Determine security context from the most recent incident
    latest_security_score = 0.0
    has_rule_match = False
    with _incidents_lock:
        if recent_incidents:
            latest = recent_incidents[-1]
            latest_security_score = max(
                float(latest.get("security_score", 0.0)),
                float(latest.get("reliability_score", 0.0)),
            )
            has_rule_match = any(
                f.get("finding_id", "").startswith("AG-RULE-")
                for f in latest.get("findings", [])
            )

    authorized, reason = policy_engine.validate_action(
        action_name=policy_action_name,
        security_score=latest_security_score,
        has_rule_match=has_rule_match,
        is_analyst_approved=request.analyst_approved,
    )
    if not authorized:
        return ActionResponse(
            success=False,
            message=f"Action DENIED by response policy: {reason}",
            receipt=None,
        )
    # ── End Policy Gate ────────────────────────────────────────────────────

    if action_type == "FREEZE_CGROUP":
        receipt = executor.freeze_cgroup(target, ttl_minutes=30)
        rollback_scheduler.schedule(receipt)
        msg = f"Cgroup '{target}' suspended non-destructively (Audit Receipt: {receipt.receipt_id})."
    elif action_type == "BLOCK_EGRESS":
        receipt = executor.block_egress(target, ttl_minutes=30)
        rollback_scheduler.schedule(receipt)
        msg = f"Outbound traffic to '{target}' blocked via firewall (Audit Receipt: {receipt.receipt_id})."
    elif action_type == "TERMINATE_PROCESS":
        pid = int(target.replace("pid:", "").replace("PID:", "")) if "pid" in target.lower() else int(target)
        receipt = executor.terminate_process(pid)
        msg = f"Process PID {pid} terminated with SIGKILL (Audit Receipt: {receipt.receipt_id})."
    elif action_type == "QUARANTINE_CONTAINER":
        receipt = executor.quarantine_container(target, ttl_minutes=60)
        rollback_scheduler.schedule(receipt)
        msg = f"Container '{target}' quarantined from network (Audit Receipt: {receipt.receipt_id})."

    return ActionResponse(success=True, message=msg, receipt=receipt.to_dict())


@app.get("/v1/actions/active", tags=["remediation"])
def list_active_actions() -> list[dict[str, Any]]:
    """List active containment actions and check expired rollbacks."""
    rollback_scheduler.check_expired()
    return [receipt.to_dict() for receipt in executor.active_actions.values()]


# Mount UI static dashboard if ui folder exists
UI_DIR = ROOT_DIR / "ui"
if UI_DIR.exists():
    app.mount("/", StaticFiles(directory=str(UI_DIR), html=True), name="ui")
