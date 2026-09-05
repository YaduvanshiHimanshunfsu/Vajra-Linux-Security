"""Risk fusion, behavioral baseline governance, and counterfactual reasoning."""

from __future__ import annotations

from math import prod

from .counterfactual import CounterfactualExplainer
from .domain import Assessment, Event, Finding
from .profiles import ProfileStore
from .reliability import ReliabilityDetector
from .rules import RuleEngine


class DetectionEngine:
    def __init__(
        self,
        rule_engine: RuleEngine,
        profiles: ProfileStore,
        reliability: ReliabilityDetector | None = None,
        explainer: CounterfactualExplainer | None = None,
    ) -> None:
        self._rules = rule_engine
        self._profiles = profiles
        self._reliability = reliability or ReliabilityDetector()
        self._explainer = explainer or CounterfactualExplainer()

    @staticmethod
    def _fuse(scores: list[float]) -> float:
        """Bayesian Noisy-OR keeps independent evidence additive without exceeding 1.0."""
        return round(1.0 - prod(1.0 - max(0.0, min(1.0, score)) for score in scores), 4) if scores else 0.0

    @staticmethod
    def _trust_findings(event: Event) -> tuple[float, list[Finding]]:
        """Score whether this event stream is authentic and safe enough to learn from or automate."""
        trust = event.trust
        # Failed host attestation (TPM quote mismatch) or compromised agent binary
        if trust.host_attestation == "failed" or trust.agent_integrity == "failed":
            return 0.0, [
                Finding(
                    detector="hardware-attestation-guard",
                    finding_id="AG-TRUST-ATTESTATION-FAILED",
                    score=0.99,
                    severity="critical",
                    evidence=[
                        f"Hardware TPM host attestation status: {trust.host_attestation}",
                        f"Sensor agent runtime integrity: {trust.agent_integrity}",
                    ],
                    recommended_action="Freeze baseline learning immediately, quarantine telemetry channel, and alert SOC for rootkit investigation.",
                )
            ]
        # Unsigned/unverified binary execution (supply chain risk)
        if event.event_type == "PROCESS_EXEC" and trust.artifact_verification == "failed":
            return 0.70, [
                Finding(
                    detector="supply-chain-guard",
                    finding_id="AG-TRUST-ARTIFACT-FAILED",
                    score=0.95,
                    severity="high",
                    evidence=[
                        f"Executed artifact '{event.subject.executable}' failed SLSA/IMA provenance signature verification",
                        f"Runtime binary SHA-256: {trust.runtime_binary_sha256 or 'unrecorded'}",
                    ],
                    mitre_techniques=["T1195", "T1204"],
                    recommended_action="Suspend workload execution and verify container image signature against CI/CD ledger.",
                )
            ]
        if trust.host_attestation == "verified" and trust.agent_integrity == "verified":
            return min(1.0, event.sensor_confidence), []
        return min(0.70, event.sensor_confidence), []

    def assess(self, event: Event, compute_counterfactual: bool = True) -> Assessment:
        """Evaluate an incoming security or telemetry event."""
        # 1. Rule violations (high-precision deterministic policies)
        rule_findings = self._rules.evaluate(event)

        # 2. Behavioral novelty (Markov process transition surprisal & destination entropy)
        behavioural_findings = self._profiles.assess(event)

        # 3. System reliability & PSI pressure forecasting
        reliability_findings = self._reliability.assess(event)

        # 4. Hardware TPM & Supply-chain trust
        telemetry_trust_score, trust_findings = self._trust_findings(event)

        # 5. Bayesian Noisy-OR Fusion
        security_findings = rule_findings + behavioural_findings + trust_findings
        security_score = self._fuse([f.score for f in security_findings])
        reliability_score = self._fuse([f.score for f in reliability_findings])

        # 6. Strict Baseline Promotion Governance:
        # Only learn events explicitly marked as verified benign, free of security/reliability risk,
        # and originating from attested hardware. Prevents attacker baseline poisoning.
        baseline_updated = False
        if (
            compute_counterfactual
            and event.attributes.get("baseline_eligible") == "true"
            and security_score < 0.25
            and reliability_score < 0.25
            and telemetry_trust_score >= 0.95
        ):
            self._profiles.learn(event)
            baseline_updated = True

        all_findings = security_findings + reliability_findings

        # 7. Automated Action Safety Rail:
        # Autonomous containment is allowed ONLY if telemetry trust is verified,
        # and security or reliability threat exceeds action threshold.
        automation_allowed = (
            telemetry_trust_score >= 0.90
            and (security_score >= 0.90 or reliability_score >= 0.80)
            and any(f.severity in ("critical", "high") for f in all_findings)
        )

        initial_assessment = Assessment(
            event_id=event.event_id,
            security_score=security_score,
            reliability_score=reliability_score,
            telemetry_trust_score=telemetry_trust_score,
            automation_allowed=automation_allowed,
            baseline_updated=baseline_updated,
            findings=all_findings,
        )

        if not compute_counterfactual:
            return initial_assessment

        # 8. Counterfactual Explainability Synthesis (Greedy L0 search)
        counterfactual = self._explainer.explain(event, initial_assessment, engine=self)

        return Assessment(
            event_id=event.event_id,
            security_score=security_score,
            reliability_score=reliability_score,
            telemetry_trust_score=telemetry_trust_score,
            automation_allowed=automation_allowed,
            baseline_updated=baseline_updated,
            findings=all_findings,
            counterfactual=counterfactual.to_dict(),
        )
