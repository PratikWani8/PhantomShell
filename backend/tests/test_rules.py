import uuid
from datetime import datetime, timedelta
import pytest

from app.schemas.event import NormalizedEvent
from app.detection.rules.unusual_process import UnusualProcessRule
from app.detection.rules.workspace_boundary import WorkspaceBoundaryRule
from app.detection.rules.file_burst import FileBurstRule
from app.detection.rules.sensitive_path import SensitivePathRule
from app.detection.rules.failed_operations import RepeatedFailedOperationsRule
from app.detection.rules.parent_child import UnusualParentChildRule
from app.detection.engine import DetectionEngine

def test_rule_unusual_process_triggers_on_flagged_tool():
    rule = UnusualProcessRule()
    
    # Event with mimikatz
    suspicious_ev = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),
        event_type="process_spawn",
        source="process_collector",
        process_name="mimikatz.exe",
        executable_path="C:\\Tools\\mimikatz.exe",
        pid=1234
    )
    res = rule.evaluate(suspicious_ev, [], {})
    assert res is not None
    assert res.triggered is True
    assert res.rule_id == "RULE_UNUSUAL_PROCESS"
    assert res.severity == "high"

    # Benign process should NOT trigger
    benign_ev = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),
        event_type="process_spawn",
        source="process_collector",
        process_name="code.exe",
        executable_path="C:\\Users\\User\\code.exe",
        pid=5678
    )
    benign_res = rule.evaluate(benign_ev, [], {})
    assert benign_res is None

def test_rule_workspace_boundary_triggers_on_blocked_traversal():
    rule = WorkspaceBoundaryRule()

    blocked_ev = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),
        event_type="command_blocked",
        source="command_collector",
        severity="medium",
        evidence={
            "command": "ls ../../../etc/shadow",
            "block_subtype": "boundary_violation_attempt",
            "reason": "Escapes workspace"
        }
    )
    res = rule.evaluate(blocked_ev, [], {})
    assert res is not None
    assert res.triggered is True
    assert res.rule_id == "RULE_WORKSPACE_BOUNDARY"

def test_rule_file_burst():
    rule = FileBurstRule()
    now = datetime.utcnow()

    # Generate 11 file modifications in 2 seconds
    past_events = [
        NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=now - timedelta(seconds=1),
            event_type="file_modify",
            source="file_collector",
            relative_path=f"file_{i}.txt"
        )
        for i in range(10)
    ]

    current_ev = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=now,
        event_type="file_modify",
        source="file_collector",
        relative_path="file_final.txt"
    )

    res = rule.evaluate(current_ev, past_events, {"file_burst_threshold": 10, "file_burst_window_seconds": 5})
    assert res is not None
    assert res.triggered is True
    assert res.rule_id == "RULE_FILE_BURST"

def test_rule_sensitive_path():
    rule = SensitivePathRule()

    ev = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),
        event_type="command_blocked",
        source="command_collector",
        evidence={"command": "cat .ssh/id_rsa"}
    )
    res = rule.evaluate(ev, [], {})
    assert res is not None
    assert res.triggered is True
    assert res.rule_id == "RULE_SENSITIVE_PATH"

def test_rule_repeated_failed_operations():
    rule = RepeatedFailedOperationsRule()
    now = datetime.utcnow()

    past_failures = [
        NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=now - timedelta(seconds=i),
            event_type="command_blocked",
            source="command_collector",
            evidence={"command": f"bad_cmd_{i}"}
        )
        for i in range(1, 3)
    ]

    current_ev = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=now,
        event_type="command_blocked",
        source="command_collector",
        evidence={"command": "bad_cmd_3"}
    )

    res = rule.evaluate(current_ev, past_failures, {"failed_op_threshold": 3, "failed_op_window_seconds": 15})
    assert res is not None
    assert res.triggered is True
    assert res.rule_id == "RULE_FAILED_OPERATIONS"

def test_rule_unusual_parent_child():
    rule = UnusualParentChildRule()

    ev = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),
        event_type="process_spawn",
        source="process_collector",
        process_name="powershell.exe",
        pid=9999,
        parent_pid=1111,
        evidence={"parent_process_name": "winword.exe"}
    )
    res = rule.evaluate(ev, [], {})
    assert res is not None
    assert res.triggered is True
    assert res.rule_id == "RULE_UNUSUAL_PARENT_CHILD"

def test_detection_engine_duplicate_suppression():
    engine = DetectionEngine()
    engine.suppression_cooldown_seconds = 5.0

    ev1 = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),
        event_type="process_spawn",
        source="process_collector",
        process_name="nc.exe",
        pid=5555
    )

    # First event should trigger incident
    incidents1 = engine.evaluate_event(ev1)
    assert len(incidents1) == 1

    # Immediate second identical event should be suppressed by cooldown
    ev2 = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),
        event_type="process_spawn",
        source="process_collector",
        process_name="nc.exe",
        pid=5556
    )
    incidents2 = engine.evaluate_event(ev2)
    assert len(incidents2) == 0
