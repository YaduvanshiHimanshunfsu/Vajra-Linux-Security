"""Scenario 3: Living-off-the-Land (LotL) Attack & Decoy File Access.

Simulates an attacker using legitimate binary /usr/bin/curl to read /etc/shadow
and exfiltrate data to an unprofiled external endpoint.
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
    lotl_file_event = Event.from_dict({
        "event_id": "evt-lotl-shadow",
        "observed_at": now,
        "host_id": "prod-srv-01",
        "boot_id": "boot-1001",
        "event_type": "FILE_ACCESS",
        "subject": {"process_id": "boot:1:701", "pid": 701, "ppid": 101, "executable": "/usr/bin/curl", "uid": 33},
        "object_type": "file",
        "object_value": "/etc/shadow",
        "workload": {"workload_id": "nginx.service", "environment": "production"},
        "result": "success",
        "attributes": {"parent_executable": "/usr/sbin/nginx_worker"},
        "trust": {"host_attestation": "verified", "agent_integrity": "verified", "artifact_verification": "verified"},
    })

    assessment = engine.assess(lotl_file_event)
    return [assessment.to_dict()]


if __name__ == "__main__":
    results = run_scenario()
    print(f"Scenario 3 completed: Security Score: {results[0]['security_score']:.2f}, Findings: {len(results[0]['findings'])}")
