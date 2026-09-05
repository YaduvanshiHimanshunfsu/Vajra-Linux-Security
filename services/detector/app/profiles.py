"""Explainable, per-workload behavioural profiles.

Implements mathematical Markov-chain process transition models, destination entropy,
and sensitive file access rarity with Laplace smoothing to prevent false-negative decay.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field

from .domain import Event, Finding


@dataclass
class WorkloadProfile:
    """Statistical profile of verified normal behavior for a specific workload identity."""

    observations: int = 0
    # Process parent -> child transition frequency
    process_transitions: Counter[tuple[str, str]] = field(default_factory=Counter)
    # Total times a specific parent spawned any process
    parent_spawn_totals: Counter[str] = field(default_factory=Counter)
    # Set of unique executables seen in this workload
    known_executables: set[str] = field(default_factory=set)
    # Network destination IP:port frequency
    network_destinations: Counter[str] = field(default_factory=Counter)
    # File access path frequency
    file_objects: Counter[str] = field(default_factory=Counter)

    def observe(self, event: Event) -> None:
        """Update normal behavior statistics from verified-benign telemetry."""
        self.observations += 1
        if event.event_type == "PROCESS_EXEC":
            parent = event.attributes.get("parent_executable", "<unknown-parent>")
            child = event.subject.executable
            self.process_transitions[(parent, child)] += 1
            self.parent_spawn_totals[parent] += 1
            self.known_executables.add(parent)
            self.known_executables.add(child)
        elif event.event_type == "NETWORK_CONNECT":
            self.network_destinations[event.object_value] += 1
        elif event.event_type == "FILE_ACCESS":
            self.file_objects[event.object_value] += 1


class ProfileStore:
    """Store of workload profiles with Laplace-smoothed probabilistic anomaly scoring."""

    def __init__(self, minimum_observations: int = 5) -> None:
        # Minimum verified events before statistical anomaly scoring activates
        self.minimum_observations = minimum_observations
        self._profiles: dict[str, WorkloadProfile] = {}

    def profile_for(self, workload_id: str) -> WorkloadProfile:
        return self._profiles.setdefault(workload_id, WorkloadProfile())

    def _transition_novelty(
        self, parent: str, child: str, profile: WorkloadProfile, alpha: float = 0.1
    ) -> tuple[float, float, int]:
        """Compute Laplace-smoothed transition probability and normalized surprisal.

        Returns:
            (novelty_score in [0, 1], transition_probability, historical_count)
        """
        count = profile.process_transitions[(parent, child)]
        parent_total = profile.parent_spawn_totals[parent]
        vocab_size = max(1, len(profile.known_executables))

        # Laplace smoothed probability P(child | parent)
        prob = (count + alpha) / (parent_total + alpha * vocab_size)

        # Theoretical minimum probability for completely unseen child from unseen parent
        max_surprisal = -math.log2(alpha / (parent_total + alpha * (vocab_size + 1)))
        actual_surprisal = -math.log2(prob)

        # Normalize surprisal into [0.0, 1.0]
        novelty = min(1.0, max(0.0, actual_surprisal / max(1.0, max_surprisal)))

        # If transition has never been seen in a mature baseline, enforce strong novelty
        if count == 0:
            novelty = max(0.85, novelty)
        elif count == 1 and profile.observations > 20:
            novelty = max(0.72, novelty)

        return round(novelty, 4), round(prob, 6), count

    def assess(self, event: Event) -> list[Finding]:
        """Evaluate incoming event against the learned normal profile."""
        profile = self.profile_for(event.workload.workload_id)
        if profile.observations < self.minimum_observations:
            return []

        findings: list[Finding] = []

        if event.event_type == "PROCESS_EXEC":
            parent = event.attributes.get("parent_executable", "<unknown-parent>")
            child = event.subject.executable
            novelty, prob, count = self._transition_novelty(parent, child, profile)

            # Novel process spawning outside established workflow
            if novelty >= 0.70:
                severity = "critical" if novelty >= 0.90 else "high" if novelty >= 0.80 else "medium"
                findings.append(
                    Finding(
                        detector="behavioural-markov-profile",
                        finding_id="AG-BEH-EXEC-NOVELTY",
                        score=novelty,
                        severity=severity,
                        evidence=[
                            f"Process transition '{parent}' -> '{child}' has empirical probability P={prob:.5f}",
                            f"Transition observed {count} times across {profile.observations} validated baseline events",
                            f"Calculated transition novelty surprisal: {novelty:.2f} / 1.00",
                        ],
                        mitre_techniques=["T1059", "T1055"],
                        recommended_action="Inspect process tree ancestry and isolate workload if not part of an approved deployment.",
                        metadata={
                            "parent": parent,
                            "child": child,
                            "transition_count": count,
                            "baseline_events": profile.observations,
                            "probability": prob,
                        },
                    )
                )

        elif event.event_type == "NETWORK_CONNECT":
            dest = event.object_value
            count = profile.network_destinations[dest]
            # Calculate rarity
            total_net = sum(profile.network_destinations.values()) or profile.observations
            prob = (count + 0.1) / (total_net + 0.1 * max(1, len(profile.network_destinations)))
            rarity = 1.0 - min(1.0, count / max(3, total_net * 0.05))

            if count == 0 or rarity >= 0.70:
                findings.append(
                    Finding(
                        detector="behavioural-network-profile",
                        finding_id="AG-BEH-NETWORK-NOVELTY",
                        score=max(0.75, round(rarity, 4)),
                        severity="high" if count == 0 else "medium",
                        evidence=[
                            f"Workload connected to unprofiled destination '{dest}' (observed {count} times in baseline)",
                            f"Total baseline network events: {total_net}",
                        ],
                        mitre_techniques=["T1071", "T1048"],
                        recommended_action="Verify remote endpoint ASN/FQDN; apply temporary egress block if unauthorized.",
                        metadata={"destination": dest, "historical_count": count},
                    )
                )

        elif event.event_type == "FILE_ACCESS":
            file_path = event.object_value
            count = profile.file_objects[file_path]
            # Sensitive path accesses (e.g. /etc/shadow, /root/.ssh, .env, credential stores)
            is_sensitive = any(
                file_path.startswith(prefix) or file_path.endswith((".env", "id_rsa", "id_ed25519", "shadow"))
                for prefix in ("/etc/shadow", "/etc/sudoers", "/root/.ssh", "/var/run/secrets")
            )
            if count == 0 and is_sensitive:
                findings.append(
                    Finding(
                        detector="behavioural-file-profile",
                        finding_id="AG-BEH-SENSITIVE-FILE-ACCESS",
                        score=0.92,
                        severity="high",
                        evidence=[
                            f"Workload accessed sensitive credential path '{file_path}' for the first time",
                            f"Baseline contains {profile.observations} events with 0 prior accesses to this object",
                        ],
                        mitre_techniques=["T1003", "T1552"],
                        recommended_action="Freeze cgroup immediately to preserve forensic memory state and investigate process credentials.",
                        metadata={"file_path": file_path, "historical_count": count},
                    )
                )

        return findings

    def learn(self, event: Event) -> None:
        """Add event to workload profile."""
        self.profile_for(event.workload.workload_id).observe(event)
