"""Vajra (वज्र) Test Lab: Master Scenario Runner.
Team: Team_Red_Eagle
Problem Statement: AI-Powered Explainable Linux Security Assistant for Kernel-Level Intrusion & Behavioral Threat Detection

Executes all 5 attack and reliability failure scenarios, validating:
1. Baseline learning on verified normal telemetry.
2. High-precision rule & anomaly detection on /tmp reverse shell.
3. Decoy file & sensitive credential access detection.
4. Linux PSI memory pressure surge proactive failure forecasting.
5. Hardware TPM attestation compromise detection and baseline freeze.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Add test-lab directory to sys.path
test_lab_dir = Path(__file__).resolve().parent
root_dir = test_lab_dir.parent
sys.path.insert(0, str(test_lab_dir))
sys.path.insert(0, str(root_dir / "services" / "detector"))

import scenario_01_normal_web
import scenario_02_tmp_reverse_shell
import scenario_03_lotl_exfiltration
import scenario_04_memory_leak_oom
import scenario_05_attestation_failure
from app.engine import DetectionEngine
from app.profiles import ProfileStore
from app.rules import RuleEngine


def main() -> None:
    print("=" * 80)
    print(">>> [7. VAJRA / वज्र] | TEAM_RED_EAGLE")
    print(">>> AI-POWERED EXPLAINABLE LINUX SECURITY ASSISTANT FOR KERNEL INTRUSION & THREAT DETECTION")
    print("=" * 80)

    engine = DetectionEngine(
        RuleEngine.from_directory(root_dir / "policy" / "detection"),
        ProfileStore(minimum_observations=2),
    )

    # 1. Normal Workload
    print("\n[+] Running Scenario 1: Benign Web Workload Normal Baseline...")
    res1 = scenario_01_normal_web.run_scenario(engine)
    print(f"    - Ingested {len(res1)} events. Baseline updated: {res1[0]['baseline_updated']}")
    print(f"    - Security Score: {res1[0]['security_score']:.2f} (Expected: <= 0.20)")
    assert res1[0]["security_score"] <= 0.20

    # 2. Reverse Shell
    print("\n[+] Running Scenario 2: /tmp Reverse Shell Intrusion...")
    res2 = scenario_02_tmp_reverse_shell.run_scenario(engine)
    print(f"    - Security Threat Score: {res2[0]['security_score']:.2f} (Expected: >= 0.90)")
    print(f"    - Findings: {[f['finding_id'] for f in res2[0]['findings']]}")
    print(f"    - Counterfactual Explanation: {res2[0]['counterfactual']['verbalized_explanation']}")
    assert res2[0]["security_score"] >= 0.90
    assert any(f["finding_id"] == "AG-RULE-001" for f in res2[0]["findings"])

    # 3. Living-off-the-Land (LotL)
    print("\n[+] Running Scenario 3: Living-off-the-Land Sensitive Decoy Access (/etc/shadow)...")
    res3 = scenario_03_lotl_exfiltration.run_scenario(engine)
    print(f"    - Security Threat Score: {res3[0]['security_score']:.2f}")
    print(f"    - Findings: {[f['finding_id'] for f in res3[0]['findings']]}")
    assert res3[0]["security_score"] >= 0.90
    assert any(f["finding_id"] == "AG-RULE-003" for f in res3[0]["findings"])

    # 4. PSI Memory Pressure Surge
    print("\n[+] Running Scenario 4: PSI Resource Pressure & Proactive Failure Forecasting...")
    res4 = scenario_04_memory_leak_oom.run_scenario(engine)
    print(f"    - Reliability Failure Score: {res4[0]['reliability_score']:.2f} (Expected: >= 0.80)")
    print(f"    - Severity: {res4[0]['findings'][0]['severity']}")
    print(f"    - Recommended Mitigation: {res4[0]['findings'][0]['recommended_action']}")
    assert res4[0]["reliability_score"] >= 0.80

    # 5. Attestation Compromise
    print("\n[+] Running Scenario 5: Hardware TPM Attestation Compromise...")
    res5 = scenario_05_attestation_failure.run_scenario(engine)
    print(f"    - Telemetry Trust Score: {res5[0]['telemetry_trust_score']:.2f} (Expected: 0.00)")
    print(f"    - Baseline Updated: {res5[0]['baseline_updated']} (Expected: False - Frozen)")
    print(f"    - Automation Allowed: {res5[0]['automation_allowed']} (Expected: False - Locked)")
    assert res5[0]["telemetry_trust_score"] == 0.0
    assert res5[0]["baseline_updated"] is False
    assert res5[0]["automation_allowed"] is False

    print("\n" + "=" * 80)
    print("[SUCCESS] ALL 5 TEST LAB SCENARIOS PASSED WITH 100% SPECIFICATION COMPLIANCE!")
    print("=" * 80)


if __name__ == "__main__":
    main()
