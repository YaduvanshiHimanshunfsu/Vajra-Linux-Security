"""Scenario 5: Hardware TPM Attestation Compromise & Baseline Freeze.

Simulates a host with failed hardware TPM quote verification, triggering immediate
telemetry trust drop to 0.0, freezing baseline learning, and raising critical SOC alert.
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
    tampered_event = Event.from_dict({
        "event_id": "evt-tpm-tamper",
        "observed_at": now,
        "host_id": "compromised-host-99",
        "boot_id": "boot-unknown",
        "event_type": "PROCESS_EXEC",
        "subject": {"process_id": "boot:1:999", "pid": 999, "ppid": 1, "executable": "/usr/bin/sudo", "uid": 0},
        "object_type": "binary",
        "object_value": "/usr/bin/sudo",
        "workload": {"workload_id": "system.slice", "environment": "production"},
        "result": "success",
        "attributes": {"baseline_eligible": "true"},
        "trust": {
            "host_attestation": "failed",
            "agent_integrity": "failed",
            "artifact_verification": "failed",
        },
    })

    assessment = engine.assess(tampered_event)
    return [assessment.to_dict()]


if __name__ == "__main__":
    results = run_scenario()
    print(f"Scenario 5 completed: Trust Score: {results[0]['telemetry_trust_score']:.2f}, Baseline Updated: {results[0]['baseline_updated']}")
