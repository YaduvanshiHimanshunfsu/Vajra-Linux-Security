"""High-precision policy rules, kept separate from ML scoring."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .domain import Event, Finding

SEVERITY_SCORE = {"low": 0.30, "medium": 0.60, "high": 0.92, "critical": 0.99}


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    title: str
    enabled: bool
    event_type: str | None
    object_type: str | None
    path_prefixes: tuple[str, ...]
    severity: str
    mitre_techniques: tuple[str, ...]
    response_mode: str
    recommended_action: str

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> "DetectionRule":
        when = document.get("when", {})
        then = document["then"]
        return cls(
            rule_id=document["id"],
            title=document["title"],
            enabled=bool(document.get("enabled", True)),
            event_type=when.get("event_type"),
            object_type=when.get("object_type"),
            path_prefixes=tuple(when.get("path_prefixes", [])),
            severity=then["severity"],
            mitre_techniques=tuple(then.get("mitre_techniques", [])),
            response_mode=then.get("response_mode", "recommend"),
            recommended_action=then.get("recommended_action", "Review process ancestry."),
        )

    def evaluate(self, event: Event) -> Finding | None:
        if not self.enabled:
            return None
        if self.event_type and event.event_type != self.event_type:
            return None
        if self.object_type and event.object_type != self.object_type:
            return None

        # Check path matching against object_value and subject executable
        if self.path_prefixes:
            target_str = event.object_value
            subject_exe = event.subject.executable
            matches = any(target_str.startswith(p) or subject_exe.startswith(p) for p in self.path_prefixes)
            if not matches:
                return None

        return Finding(
            detector="policy-rule-engine",
            finding_id=self.rule_id,
            score=SEVERITY_SCORE.get(self.severity, 0.50),
            severity=self.severity,
            evidence=[
                f"{self.title}: observed {event.event_type} for {event.object_value}",
                f"Workload identity: {event.workload.workload_id}",
            ],
            mitre_techniques=list(self.mitre_techniques),
            recommended_action=self.recommended_action,
            metadata={"response_mode": self.response_mode},
        )


class RuleEngine:
    def __init__(self, rules: list[DetectionRule]) -> None:
        self._rules = rules

    @classmethod
    def from_directory(cls, policy_dir: Path) -> "RuleEngine":
        rules = []
        if policy_dir.exists():
            for path in sorted(policy_dir.glob("*.yaml")):
                with path.open(encoding="utf-8") as policy_file:
                    rules.append(DetectionRule.from_dict(yaml.safe_load(policy_file)))
        return cls(rules)

    def evaluate(self, event: Event) -> list[Finding]:
        return [finding for rule in self._rules if (finding := rule.evaluate(event))]
