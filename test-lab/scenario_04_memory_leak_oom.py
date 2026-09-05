"""Scenario 4: System Reliability - Sudden Memory Leak & PSI Pressure Surge.

Simulates a runaway memory allocation triggering Linux Pressure Stall Information (PSI)
spikes to forecast OOM kills before the system crashes.
"""

from __future__ import annotations

from datetime import datetime, timezone
import sys
from pathlib import Path

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
    pressure_event = Event.from_dict({
        "event_id": "evt-leak-psi",
        "observed_at": now,
        "host_id": "prod-srv-01",
        "boot_id": "boot-1001",
        "event_type": "RESOURCE_PRESSURE",
        "subject": {"process_id": "boot:1:100", "pid": 100, "ppid": 1, "executable": "/usr/sbin/nginx", "uid": 33},
        "object_type": "cgroup",
        "object_value": "/sys/fs/cgroup/system.slice/nginx.service",
        "workload": {"workload_id": "nginx.service", "environment": "production"},
        "result": "success",
        "attributes": {
            "resource": "memory",
            "pressure_ratio": "0.91",
            "full_pressure_ratio": "0.62",
            "cgroup": "nginx.service",
        },
        "trust": {"host_attestation": "verified", "agent_integrity": "verified", "artifact_verification": "verified"},
    })

    assessment = engine.assess(pressure_event)
    return [assessment.to_dict()]


if __name__ == "__main__":
    results = run_scenario()
    print(f"Scenario 4 completed: Reliability Score: {results[0]['reliability_score']:.2f}, Severity: {results[0]['findings'][0]['severity']}")
