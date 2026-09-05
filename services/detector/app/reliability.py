"""Proactive Linux system failure and resource exhaustion detection.

Tracks Linux Pressure Stall Information (PSI) for memory, CPU, and I/O using
Exponential Weighted Moving Average (EWMA) and dynamic outlier scoring to forecast
Out-Of-Memory (OOM) kills, thread starvation, and kernel lockups before failure occurs.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from .domain import Event, Finding


@dataclass
class ResourceState:
    """State tracking for a specific host/cgroup resource metric."""

    observations: int = 0
    ewma_mean: float = 0.0
    ewma_var: float = 0.0
    last_value: float = 0.0
    last_timestamp: float = 0.0


class ReliabilityDetector:
    """Detects reliability degradation and predicts impending system failures."""

    def __init__(self, alpha: float = 0.2, alert_threshold_z: float = 2.5) -> None:
        self.alpha = alpha  # EWMA decay factor
        self.alert_threshold_z = alert_threshold_z
        self._states: dict[str, ResourceState] = {}

    def _get_state(self, key: str) -> ResourceState:
        return self._states.setdefault(key, ResourceState())

    def assess(self, event: Event) -> list[Finding]:
        """Assess system reliability from resource telemetry events."""
        if event.event_type != "RESOURCE_PRESSURE":
            return []

        resource = event.attributes.get("resource", "memory").lower()
        pressure_ratio = float(event.attributes.get("pressure_ratio", "0.0"))
        full_pressure = float(event.attributes.get("full_pressure_ratio", "0.0"))
        cgroup = event.attributes.get("cgroup", event.workload.workload_id)

        key = f"{event.host_id}:{cgroup}:{resource}"
        state = self._get_state(key)

        state.observations += 1

        # Online update of EWMA mean and variance
        diff = pressure_ratio - state.ewma_mean
        state.ewma_mean += self.alpha * diff
        state.ewma_var = (1 - self.alpha) * (state.ewma_var + self.alpha * diff * diff)
        std_dev = math.sqrt(max(1e-6, state.ewma_var))

        # Velocity: rate of pressure increase
        delta_p = pressure_ratio - state.last_value
        state.last_value = pressure_ratio

        # Calculate anomaly severity score
        # 1. Base pressure magnitude score (pressure >= 0.5 is acute, >= 0.8 is critical)
        magnitude_score = min(1.0, pressure_ratio / 0.80)

        # 2. Rate of surge (fast spikes represent sudden runaway leaks or forkbombs)
        surge_score = min(1.0, max(0.0, delta_p / 0.30))

        # Combined reliability risk score
        combined_score = min(0.99, max(magnitude_score, 0.7 * magnitude_score + 0.3 * surge_score))

        if pressure_ratio < 0.20 and surge_score < 0.50:
            return []

        severity = "critical" if combined_score >= 0.85 else "high" if combined_score >= 0.60 else "medium"

        # Construct explanation and remediation guidance
        if resource == "memory":
            rec_action = (
                "Throttle cgroup memory limit or freeze low-priority background workers before kernel OOM reaper kills main service."
                if severity == "critical"
                else "Inspect process heap allocation and scale memory quota."
            )
        elif resource == "cpu":
            rec_action = "Inspect runnable task queue depth and isolate runaway compute loops."
        else:
            rec_action = "Shed background I/O intensive workers to prevent storage starvation."

        finding = Finding(
            detector="reliability-psi-forecaster",
            finding_id="AG-REL-PRESSURE-FORECAST",
            score=round(combined_score, 4),
            severity=severity,
            evidence=[
                f"Linux {resource.upper()} pressure stall ratio reached {pressure_ratio:.2f} (Full stall: {full_pressure:.2f})",
                f"EWMA baseline mean: {state.ewma_mean:.3f}, std dev: {std_dev:.3f}",
                f"Instantaneous surge velocity: +{delta_p:.2f} per interval",
                f"Affected workload/cgroup: {cgroup}",
            ],
            recommended_action=rec_action,
            metadata={
                "resource": resource,
                "pressure_ratio": pressure_ratio,
                "full_pressure": full_pressure,
                "surge_velocity": delta_p,
                "cgroup": cgroup,
            },
        )
        return [finding]
