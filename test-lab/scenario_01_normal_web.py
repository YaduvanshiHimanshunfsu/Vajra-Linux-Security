"""Scenario 1: Benign Web Service Normal Baseline Training.

Simulates legitimate systemd process spawning nginx master and worker processes,
accessing configuration files, and accepting inbound HTTP requests.
"""

from __future__ import annotations

from datetime import datetime, timezone
import sys
from pathlib import Path

# Add services root to sys.path
root_dir = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root_dir / "services" / "detector"))

from app.domain import Event
from app.engine import DetectionEngine
from app.profiles import ProfileStore
from app.rules import RuleEngine


def run_scenario(engine: DetectionEngine | None = None) -> list[dict]:
    if engine is None:
        engine = DetectionEngine(
            RuleEngine.from_directory(root_dir / "policy" / "detection"),
            ProfileStore(minimum_observations=3),
        )

    now = datetime.now(timezone.utc).isoformat()
    events = [
        Event.from_dict({
            "event_id": "evt-web-init",
            "observed_at": now,
            "host_id": "prod-srv-01",
            "boot_id": "boot-1001",
            "event_type": "PROCESS_EXEC",
            "subject": {"process_id": "boot:1:100", "pid": 100, "ppid": 1, "executable": "/usr/sbin/nginx", "uid": 0},
            "object_type": "binary",
            "object_value": "/usr/sbin/nginx",
            "workload": {"workload_id": "nginx.service", "environment": "production"},
            "result": "success",
            "attributes": {"baseline_eligible": "true", "parent_executable": "/usr/lib/systemd/systemd"},
            "trust": {"host_attestation": "verified", "agent_integrity": "verified", "artifact_verification": "verified"},
        }),
        Event.from_dict({
            "event_id": "evt-web-worker",
            "observed_at": now,
            "host_id": "prod-srv-01",
            "boot_id": "boot-1001",
            "event_type": "PROCESS_EXEC",
            "subject": {"process_id": "boot:1:101", "pid": 101, "ppid": 100, "executable": "/usr/sbin/nginx_worker", "uid": 33},
            "object_type": "binary",
            "object_value": "/usr/sbin/nginx_worker",
            "workload": {"workload_id": "nginx.service", "environment": "production"},
            "result": "success",
            "attributes": {"baseline_eligible": "true", "parent_executable": "/usr/sbin/nginx"},
            "trust": {"host_attestation": "verified", "agent_integrity": "verified", "artifact_verification": "verified"},
        }),
    ]

    assessments = []
    for evt in events:
        assessment = engine.assess(evt)
        assessments.append(assessment.to_dict())
    return assessments


if __name__ == "__main__":
    results = run_scenario()
    print(f"Scenario 1 completed: {len(results)} events evaluated. Max Security Risk: {max(r['security_score'] for r in results):.2f}")
