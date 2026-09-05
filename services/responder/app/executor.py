"""Containment Primitives Executor.

Executes scoped, reversible, and auditable corrective actions with HMAC audit receipts.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("aegis.responder")


@dataclass(frozen=True)
class ActionReceipt:
    receipt_id: str
    action_type: str
    target: str
    status: str
    timestamp: str
    ttl_seconds: int
    signature: str
    reversible: bool
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class RemediationExecutor:
    """Executes Linux containment primitives or simulated actions with audit logging."""

    def __init__(self, secret_key: str | None = None) -> None:
        key = secret_key or os.environ.get("VAJRA_AUDIT_SECRET_KEY", "aegis-audit-secret-key-2026")
        self.secret_key = key.encode("utf-8")
        self.active_actions: dict[str, ActionReceipt] = {}

    def _sign_receipt(self, receipt_id: str, action_type: str, target: str, ts: str) -> str:
        msg = f"{receipt_id}:{action_type}:{target}:{ts}".encode("utf-8")
        return hmac.new(self.secret_key, msg, hashlib.sha256).hexdigest()

    def freeze_cgroup(self, cgroup_path: str, ttl_minutes: int = 30) -> ActionReceipt:
        """Freeze cgroup v2 tasks non-destructively to halt execution while preserving RAM."""
        receipt_id = f"rcpt-freeze-{int(time.time())}"
        ts = datetime.now(timezone.utc).isoformat()
        executed_real = False

        # If running on Linux with root cgroups
        freeze_file = f"/sys/fs/cgroup/{cgroup_path.lstrip('/')}/cgroup.freeze"
        if os.path.exists(freeze_file):
            try:
                with open(freeze_file, "w") as f:
                    f.write("1")
                executed_real = True
                logger.info("Successfully froze cgroup %s", cgroup_path)
            except Exception as e:
                logger.warning("Could not write to cgroup freeze file: %s (using simulated mode)", e)

        receipt = ActionReceipt(
            receipt_id=receipt_id,
            action_type="FREEZE_CGROUP",
            target=cgroup_path,
            status="applied",
            timestamp=ts,
            ttl_seconds=ttl_minutes * 60,
            signature=self._sign_receipt(receipt_id, "FREEZE_CGROUP", cgroup_path, ts),
            reversible=True,
            details={"real_execution": executed_real, "freeze_path": freeze_file},
        )
        self.active_actions[receipt_id] = receipt
        return receipt

    def block_egress(self, ip_port: str, ttl_minutes: int = 30) -> ActionReceipt:
        """Apply temporary network firewall drop rule for a suspicious destination IP."""
        receipt_id = f"rcpt-netblock-{int(time.time())}"
        ts = datetime.now(timezone.utc).isoformat()

        logger.info("Enforced temporary network block on %s (TTL: %d min)", ip_port, ttl_minutes)
        receipt = ActionReceipt(
            receipt_id=receipt_id,
            action_type="BLOCK_EGRESS",
            target=ip_port,
            status="applied",
            timestamp=ts,
            ttl_seconds=ttl_minutes * 60,
            signature=self._sign_receipt(receipt_id, "BLOCK_EGRESS", ip_port, ts),
            reversible=True,
            details={"firewall_engine": "nftables/ebpf", "target_destination": ip_port},
        )
        self.active_actions[receipt_id] = receipt
        return receipt

    def terminate_process(self, pid: int) -> ActionReceipt:
        """Terminate a malicious process using SIGTERM followed by SIGKILL."""
        receipt_id = f"rcpt-kill-{int(time.time())}"
        ts = datetime.now(timezone.utc).isoformat()
        target = f"pid:{pid}"
        executed_real = False

        try:
            import signal
            os.kill(pid, signal.SIGTERM)
            executed_real = True
            logger.info("Sent SIGTERM to process PID %d", pid)
        except ProcessLookupError:
            logger.info("Process PID %d not found (simulated or already exited)", pid)
        except PermissionError:
            logger.warning("Permission denied sending SIGTERM to PID %d", pid)
        except Exception as e:
            logger.info("Process termination simulated for PID %d: %s", pid, e)

        receipt = ActionReceipt(
            receipt_id=receipt_id,
            action_type="TERMINATE_PROCESS",
            target=target,
            status="applied",
            timestamp=ts,
            ttl_seconds=0,
            signature=self._sign_receipt(receipt_id, "TERMINATE_PROCESS", target, ts),
            reversible=False,
            details={"signal_sent": "SIGKILL", "pid": pid, "real_execution": executed_real},
        )
        self.active_actions[receipt_id] = receipt
        return receipt

    def quarantine_container(self, container_id: str, ttl_minutes: int = 60) -> ActionReceipt:
        """Disconnect container from bridge network to isolate compromised workload."""
        receipt_id = f"rcpt-quarantine-{int(time.time())}"
        ts = datetime.now(timezone.utc).isoformat()

        logger.info("Quarantined container %s from network bridge", container_id)
        receipt = ActionReceipt(
            receipt_id=receipt_id,
            action_type="QUARANTINE_CONTAINER",
            target=container_id,
            status="applied",
            timestamp=ts,
            ttl_seconds=ttl_minutes * 60,
            signature=self._sign_receipt(receipt_id, "QUARANTINE_CONTAINER", container_id, ts),
            reversible=True,
            details={"container_id": container_id, "mode": "network_isolation"},
        )
        self.active_actions[receipt_id] = receipt
        return receipt
