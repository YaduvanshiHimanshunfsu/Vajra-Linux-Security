"""Unit tests for the Responder service — executor, policy checker, and rollback."""

from __future__ import annotations

import sys
from pathlib import Path

# Add service directory to sys.path
service_dir = Path(__file__).resolve().parents[1]
if str(service_dir) not in sys.path:
    sys.path.insert(0, str(service_dir))

from app.executor import RemediationExecutor
from app.policy_checker import ResponsePolicyEngine
from app.rollback import RollbackScheduler


# ── Executor Tests ──


def test_freeze_cgroup_creates_receipt() -> None:
    executor = RemediationExecutor()
    receipt = executor.freeze_cgroup("test.service", ttl_minutes=15)
    assert receipt.action_type == "FREEZE_CGROUP"
    assert receipt.target == "test.service"
    assert receipt.status == "applied"
    assert receipt.reversible is True
    assert receipt.ttl_seconds == 15 * 60
    assert receipt.receipt_id in executor.active_actions


def test_block_egress_creates_receipt() -> None:
    executor = RemediationExecutor()
    receipt = executor.block_egress("10.0.0.1:4444", ttl_minutes=30)
    assert receipt.action_type == "BLOCK_EGRESS"
    assert receipt.reversible is True
    assert len(receipt.signature) == 64  # SHA-256 hex digest length


def test_terminate_process_is_not_reversible() -> None:
    executor = RemediationExecutor()
    receipt = executor.terminate_process(pid=9999)
    assert receipt.action_type == "TERMINATE_PROCESS"
    assert receipt.reversible is False
    assert receipt.ttl_seconds == 0


def test_quarantine_container_creates_receipt() -> None:
    executor = RemediationExecutor()
    receipt = executor.quarantine_container("abc123", ttl_minutes=60)
    assert receipt.action_type == "QUARANTINE_CONTAINER"
    assert receipt.ttl_seconds == 60 * 60


def test_receipt_hmac_signature_is_deterministic() -> None:
    executor = RemediationExecutor(secret_key="test-key")
    r1 = executor._sign_receipt("id1", "FREEZE", "target1", "2026-01-01T00:00:00Z")
    r2 = executor._sign_receipt("id1", "FREEZE", "target1", "2026-01-01T00:00:00Z")
    assert r1 == r2  # Same inputs produce same signature


def test_receipt_hmac_changes_with_different_input() -> None:
    executor = RemediationExecutor(secret_key="test-key")
    r1 = executor._sign_receipt("id1", "FREEZE", "target1", "2026-01-01T00:00:00Z")
    r2 = executor._sign_receipt("id2", "FREEZE", "target1", "2026-01-01T00:00:00Z")
    assert r1 != r2


# ── Policy Checker Tests ──


def test_policy_engine_loads_from_yaml() -> None:
    root = Path(__file__).resolve().parents[3]
    engine = ResponsePolicyEngine.from_file(root / "policy" / "response" / "response_policy.yaml")
    assert engine.version == 1
    assert len(engine.actions) >= 1


def test_policy_engine_allows_authorized_action() -> None:
    policy_data = {
        "version": 1,
        "defaults": {"minimum_security_score": 0.90},
        "actions": {
            "freeze_cgroup": {"allowed": True, "requires_rule_match": False},
        },
    }
    engine = ResponsePolicyEngine(policy_data)
    authorized, reason = engine.validate_action("freeze_cgroup", security_score=0.95, has_rule_match=False)
    assert authorized is True


def test_policy_engine_denies_low_score() -> None:
    policy_data = {
        "version": 1,
        "defaults": {"minimum_security_score": 0.90},
        "actions": {
            "freeze_cgroup": {"allowed": True},
        },
    }
    engine = ResponsePolicyEngine(policy_data)
    authorized, reason = engine.validate_action("freeze_cgroup", security_score=0.50, has_rule_match=False)
    assert authorized is False
    assert "below policy threshold" in reason


def test_policy_engine_denies_disabled_action() -> None:
    policy_data = {
        "version": 1,
        "defaults": {"minimum_security_score": 0.50},
        "actions": {
            "delete_file": {"allowed": False},
        },
    }
    engine = ResponsePolicyEngine(policy_data)
    authorized, reason = engine.validate_action("delete_file", security_score=1.0, has_rule_match=True)
    assert authorized is False
    assert "disabled" in reason


def test_policy_engine_denies_unknown_action() -> None:
    engine = ResponsePolicyEngine({"version": 1, "defaults": {}, "actions": {}})
    authorized, reason = engine.validate_action("nuke_everything", security_score=1.0, has_rule_match=True)
    assert authorized is False
    assert "not recognized" in reason


def test_policy_engine_requires_analyst_approval() -> None:
    policy_data = {
        "version": 1,
        "defaults": {"minimum_security_score": 0.50},
        "actions": {
            "quarantine": {"allowed": True, "requires_analyst_approval": True},
        },
    }
    engine = ResponsePolicyEngine(policy_data)
    denied, _ = engine.validate_action("quarantine", security_score=1.0, has_rule_match=True, is_analyst_approved=False)
    assert denied is False
    approved, _ = engine.validate_action("quarantine", security_score=1.0, has_rule_match=True, is_analyst_approved=True)
    assert approved is True


# ── Rollback Scheduler Tests ──


def test_rollback_scheduler_does_not_schedule_irreversible() -> None:
    executor = RemediationExecutor()
    scheduler = RollbackScheduler()
    receipt = executor.terminate_process(pid=1234)
    scheduler.schedule(receipt)
    assert len(scheduler._scheduled_rollbacks) == 0


def test_rollback_scheduler_schedules_reversible() -> None:
    executor = RemediationExecutor()
    scheduler = RollbackScheduler()
    receipt = executor.freeze_cgroup("test.service", ttl_minutes=1)
    scheduler.schedule(receipt)
    assert len(scheduler._scheduled_rollbacks) == 1
    assert scheduler._scheduled_rollbacks[receipt.receipt_id]["rolled_back"] is False


def test_rollback_scheduler_execute_simulated_rollback() -> None:
    executor = RemediationExecutor()
    scheduler = RollbackScheduler()
    receipt = executor.block_egress("192.168.1.1:80", ttl_minutes=0)
    success = scheduler._execute_rollback(receipt)
    assert success is True
