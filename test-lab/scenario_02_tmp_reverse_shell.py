"""Scenario 2: Security Intrusion - Execution from /tmp with Reverse Shell.

Simulates an attacker writing an unsigned payload to /tmp/kworker_rev, executing it
under the web server process context, and initiating an outbound socket connection.
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
    attack_event = Event.from_dict({
        "event_id": "evt-attack-revshell",
        "observed_at": now,
        "host_id": "prod-srv-01",
        "boot_id": "boot-1001",
        "event_type": "PROCESS_EXEC",
        "subject": {"process_id": "boot:1:666", "pid": 666, "ppid": 101, "executable": "/tmp/kworker_rev", "uid": 33},
        "object_type": "binary",
        "object_value": "/tmp/kworker_rev",
        "workload": {"workload_id": "nginx.service", "environment": "production"},
        "result": "success",
        "attributes": {"parent_executable": "/usr/sbin/nginx_worker"},
        "trust": {
            "host_attestation": "verified",
            "agent_integrity": "verified",
            "artifact_verification": "failed",
            "runtime_binary_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        },
    })

    assessment = engine.assess(attack_event)
    return [assessment.to_dict()]


if __name__ == "__main__":
    results = run_scenario()
    print(f"Scenario 2 completed: Security Score: {results[0]['security_score']:.2f}, Findings: {len(results[0]['findings'])}")
