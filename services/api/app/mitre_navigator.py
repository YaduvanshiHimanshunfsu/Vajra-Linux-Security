"""MITRE ATT&CK Navigator Layer v4.5 JSON Exporter.

Generates official MITRE ATT&CK Navigator matrix layers from detected runtime threats
for direct import into enterprise SOC visualization tools (https://mitre-attack.github.io/attack-navigator/).
"""

from __future__ import annotations

from typing import Any

TECHNIQUE_METADATA: dict[str, dict[str, str]] = {
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "execution"},
    "T1059.004": {"name": "Unix Shell", "tactic": "execution"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "credential-access"},
    "T1003.008": {"name": "/etc/passwd and /etc/shadow", "tactic": "credential-access"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "command-and-control"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "exfiltration"},
    "T1055": {"name": "Process Injection", "tactic": "defense-evasion"},
    "T1195": {"name": "Supply Chain Compromise", "tactic": "initial-access"},
    "T1204": {"name": "User Execution", "tactic": "execution"},
    "T1552": {"name": "Unsecured Credentials", "tactic": "credential-access"},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "privilege-escalation"},
}


class MitreNavigatorExporter:
    @staticmethod
    def generate_layer(incidents: list[dict[str, Any]]) -> dict[str, Any]:
        """Generate a complete MITRE ATT&CK Navigator Layer v4 JSON object."""
        technique_scores: dict[str, dict[str, Any]] = {}

        # Aggregate detected techniques and their highest severity scores
        for inc in incidents:
            findings = inc.get("findings", [])
            sec_score = inc.get("security_score", 0.0)
            workload = inc.get("event", {}).get("workload", {}).get("workload_id", "workload")
            event_type = inc.get("event", {}).get("event_type", "EVENT")

            for f in findings:
                for tech_id in f.get("mitre_techniques", []):
                    tech_clean = tech_id.strip()
                    if tech_clean not in technique_scores:
                        technique_scores[tech_clean] = {
                            "score": sec_score,
                            "comments": [f"[{workload}] {event_type}: {f.get('recommended_action', '')}"],
                        }
                    else:
                        existing = technique_scores[tech_clean]
                        if sec_score > existing["score"]:
                            existing["score"] = sec_score
                        existing["comments"].append(f"[{workload}] {event_type}")

        techniques_list: list[dict[str, Any]] = []

        # Color ramp: Green (0.2) -> Yellow (0.5) -> Orange (0.75) -> Red (0.90+)
        for tech_id, data in technique_scores.items():
            score = round(data["score"], 2)
            color = (
                "#ff3366" if score >= 0.85 else "#ff9900" if score >= 0.60 else "#ffcc00" if score >= 0.30 else "#00e676"
            )
            meta = TECHNIQUE_METADATA.get(tech_id, {"tactic": "execution"})
            comments_joined = " | ".join(data["comments"][:3])

            techniques_list.append(
                {
                    "techniqueID": tech_id,
                    "tactic": meta.get("tactic", "execution"),
                    "score": score,
                    "color": color,
                    "comment": f"Vajra Runtime Detection (Score: {score:.2f}) - {comments_joined}",
                    "enabled": True,
                    "showSubtechniques": True,
                }
            )

        # Build official MITRE ATT&CK Navigator v4.5 schema
        layer = {
            "name": "वज्र (Vajra) Threat Detection Layer - Team Red Eagle",
            "versions": {
                "attack": "15",
                "navigator": "4.5",
                "layer": "4.5",
            },
            "domain": "enterprise-attack",
            "description": "Real-time kernel-level intrusion & behavioral threats detected by Vajra on Linux hosts.",
            "gradient": {
                "colors": ["#00e676", "#ffcc00", "#ff9900", "#ff3366"],
                "minValue": 0.2,
                "maxValue": 1.0,
            },
            "legendItems": [
                {"label": "Critical Threat (0.85 - 1.00)", "color": "#ff3366"},
                {"label": "High Anomaly (0.60 - 0.84)", "color": "#ff9900"},
                {"label": "Medium Risk (0.30 - 0.59)", "color": "#ffcc00"},
                {"label": "Low / Informational (< 0.30)", "color": "#00e676"},
            ],
            "techniques": techniques_list,
        }
        return layer
