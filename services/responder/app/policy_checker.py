"""Policy validation and authorization for containment actions."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class PolicyActionRule:
    name: str
    allowed: bool
    requires_rule_match: bool = False
    requires_analyst_approval: bool = False
    max_ttl_minutes: int = 30
    rollback_handler: str = ""


class ResponsePolicyEngine:
    def __init__(self, policy_data: dict[str, Any]) -> None:
        self.version = policy_data.get("version", 1)
        self.defaults = policy_data.get("defaults", {})
        self.actions: dict[str, PolicyActionRule] = {}

        for action_name, config in policy_data.get("actions", {}).items():
            self.actions[action_name] = PolicyActionRule(
                name=action_name,
                allowed=bool(config.get("allowed", False)),
                requires_rule_match=bool(config.get("requires_rule_match", False)),
                requires_analyst_approval=bool(config.get("requires_analyst_approval", False)),
                max_ttl_minutes=int(config.get("max_ttl_minutes", 30)),
                rollback_handler=str(config.get("rollback", "")),
            )

    @classmethod
    def from_file(cls, policy_path: Path) -> "ResponsePolicyEngine":
        if not policy_path.exists():
            # Return safe default
            return cls({"version": 1, "defaults": {"mode": "recommend"}, "actions": {}})
        with policy_path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls(data)

    def validate_action(
        self,
        action_name: str,
        security_score: float,
        has_rule_match: bool,
        is_analyst_approved: bool = False,
    ) -> tuple[bool, str]:
        """Verify whether an action is authorized under current policy rules."""
        rule = self.actions.get(action_name)
        if not rule:
            return False, f"Action '{action_name}' is not recognized in response policy."
        if not rule.allowed:
            return False, f"Action '{action_name}' is explicitly disabled in policy."

        min_score = float(self.defaults.get("minimum_security_score", 0.90))
        if security_score < min_score:
            return False, f"Security score {security_score:.2f} is below policy threshold {min_score:.2f}."

        if rule.requires_rule_match and not has_rule_match:
            return False, f"Action '{action_name}' strictly requires a verified rule match."

        if rule.requires_analyst_approval and not is_analyst_approved:
            return False, f"Action '{action_name}' requires manual security analyst authorization."

        return True, "Action authorized by policy."
