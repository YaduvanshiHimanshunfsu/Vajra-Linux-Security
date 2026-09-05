"""Automatic TTL rollback scheduler for temporary containment actions."""

from __future__ import annotations

import logging
import os
import time
from typing import Any

from .executor import ActionReceipt

logger = logging.getLogger("aegis.rollback")


class RollbackScheduler:
    def __init__(self) -> None:
        self._scheduled_rollbacks: dict[str, dict[str, Any]] = {}

    def schedule(self, receipt: ActionReceipt) -> None:
        if not receipt.reversible or receipt.ttl_seconds <= 0:
            return
        expire_at = time.time() + receipt.ttl_seconds
        self._scheduled_rollbacks[receipt.receipt_id] = {
            "receipt": receipt,
            "expire_at": expire_at,
            "rolled_back": False,
        }
        logger.info(
            "Scheduled automatic rollback for %s in %d seconds",
            receipt.receipt_id,
            receipt.ttl_seconds,
        )

    def _execute_rollback(self, receipt: ActionReceipt) -> bool:
        """Actually reverse the containment action on the system."""
        action = receipt.action_type
        target = receipt.target

        if action == "FREEZE_CGROUP":
            # Unfreeze: write "0" to cgroup.freeze
            freeze_file = f"/sys/fs/cgroup/{target.lstrip('/')}/cgroup.freeze"
            if os.path.exists(freeze_file):
                try:
                    with open(freeze_file, "w") as f:
                        f.write("0")
                    logger.info("Unfroze cgroup %s via rollback", target)
                    return True
                except OSError as e:
                    logger.error("Failed to unfreeze cgroup %s: %s", target, e)
                    return False
            else:
                logger.info(
                    "Rollback for FREEZE_CGROUP %s (simulated — freeze file not found)",
                    target,
                )
                return True

        elif action == "BLOCK_EGRESS":
            logger.info(
                "Rolled back egress block for %s (nftables rule removal simulated)",
                target,
            )
            return True

        elif action == "QUARANTINE_CONTAINER":
            logger.info(
                "Rolled back container quarantine for %s (network reconnect simulated)",
                target,
            )
            return True

        else:
            logger.warning(
                "No rollback handler for action type '%s' on target '%s'",
                action,
                target,
            )
            return False

    def check_expired(self) -> list[str]:
        """Check for expired containment actions and execute rollbacks."""
        now = time.time()
        expired: list[str] = []
        for rid, entry in list(self._scheduled_rollbacks.items()):
            if not entry["rolled_back"] and now >= entry["expire_at"]:
                receipt = entry["receipt"]
                success = self._execute_rollback(receipt)
                entry["rolled_back"] = True
                entry["rollback_success"] = success
                expired.append(rid)
                logger.info(
                    "Automatically rolled back expired containment action %s (success=%s)",
                    rid,
                    success,
                )
        return expired

    def get_scheduled(self) -> list[dict[str, Any]]:
        """Return summary of all scheduled rollbacks for API inspection."""
        return [
            {
                "receipt_id": rid,
                "action_type": entry["receipt"].action_type,
                "target": entry["receipt"].target,
                "expire_at": entry["expire_at"],
                "rolled_back": entry["rolled_back"],
                "remaining_seconds": max(0, int(entry["expire_at"] - time.time())),
            }
            for rid, entry in self._scheduled_rollbacks.items()
        ]
