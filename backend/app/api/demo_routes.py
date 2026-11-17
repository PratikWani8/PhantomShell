import asyncio
import json
import random
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.event import EventModel
from app.models.incident import IncidentModel
from app.schemas.event import NormalizedEvent
from app.services.monitoring_service import monitoring_service
from app.websocket.connection_manager import ws_manager

demo_router = APIRouter(prefix="/api/demo", tags=["Demo Mode"])

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "demo" / "fixtures"

def _load_fixtures() -> List[Dict[str, Any]]:
    path = FIXTURES_DIR / "demo_events.json"
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

@demo_router.post("/run-curated")
async def run_curated_sequence():
    """
    Executes a structured 7-step simulated demonstration:
    1. Normal file creations (benign)
    2. File burst anomaly
    3. Blocked boundary traversal attempt
    4. Sensitive credential access probe
    5. High-risk offensive utility detection
    All events are marked is_simulated=True.
    """
    results = []

    # 1. Normal benign event
    benign_event = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),
        event_type="file_create",
        source="demo_fixture",
        severity="info",
        relative_path="src/components/Header.tsx",
        evidence={"operation": "create", "note": "Benign component creation", "is_simulated": True},
        collection_status="collected",
        is_simulated=True
    )
    await monitoring_service._process_event_async(benign_event)
    results.append("Emitted benign file creation")

    # 2. File burst anomaly (12 rapid file events)
    for i in range(12):
        burst_ev = NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            event_type="file_modify",
            source="demo_fixture",
            severity="info",
            relative_path=f"documents/encrypted_doc_{i}.vault",
            evidence={"operation": "modify", "batch_index": i, "is_simulated": True},
            collection_status="collected",
            is_simulated=True
        )
        await monitoring_service._process_event_async(burst_ev)
    results.append("Emitted 12 file modification burst events (Triggered RULE_FILE_BURST)")

    # 3. Blocked boundary traversal attempt
    boundary_ev = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),
        event_type="command_blocked",
        source="command_collector",
        severity="medium",
        evidence={
            "command": "ls ../../../Windows/System32",
            "block_subtype": "boundary_violation_attempt",
            "reason": "Boundary violation: Path escapes workspace root",
            "is_simulated": True
        },
        collection_status="blocked",
        is_simulated=True
    )
    await monitoring_service._process_event_async(boundary_ev)
    results.append("Emitted out-of-boundary probe (Triggered RULE_WORKSPACE_BOUNDARY)")

    # 4. Sensitive credential probe
    sens_ev = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),
        event_type="command_blocked",
        source="command_collector",
        severity="high",
        evidence={
            "command": "scan .ssh/id_rsa",
            "block_subtype": "security_scan_alert",
            "reason": "Protected sensitive resource targeted: .ssh/id_rsa",
            "is_simulated": True
        },
        collection_status="blocked",
        is_simulated=True
    )
    await monitoring_service._process_event_async(sens_ev)
    results.append("Emitted credential probe (Triggered RULE_SENSITIVE_PATH)")

    # 5. Suspicious process
    proc_ev = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),
        event_type="process_spawn",
        source="process_collector",
        severity="high",
        pid=9821,
        process_name="mimikatz.exe",
        executable_path="C:\\Tools\\mimikatz.exe",
        parent_pid=1024,
        evidence={
            "process_name": "mimikatz.exe",
            "pid": 9821,
            "executable_path": "C:\\Tools\\mimikatz.exe",
            "matched_pattern": "mimikatz.exe",
            "is_simulated": True
        },
        collection_status="collected",
        is_simulated=True
    )
    await monitoring_service._process_event_async(proc_ev)
    results.append("Emitted suspicious tool spawn (Triggered RULE_UNUSUAL_PROCESS)")

    return {
        "status": "success",
        "message": "Curated demonstration sequence completed successfully.",
        "steps_executed": results,
        "is_simulated": True
    }

@demo_router.post("/run-random")
async def run_random_scenario():
    """Generates a randomized sequence from validated event templates."""
    templates = [
        {
            "event_type": "process_spawn",
            "source": "process_collector",
            "severity": "high",
            "process_name": random.choice(["nc.exe", "ncat.exe", "psexec.exe", "procdump.exe"]),
            "executable_path": "C:\\Windows\\Temp\\probe.exe",
            "pid": random.randint(5000, 9999),
            "evidence": {"is_simulated": True, "note": "Randomized simulated tool launch"}
        },
        {
            "event_type": "command_blocked",
            "source": "command_collector",
            "severity": "medium",
            "evidence": {
                "command": f"ls ../../system_{random.randint(10,99)}",
                "block_subtype": "boundary_violation_attempt",
                "reason": "Simulated traversal attempt",
                "is_simulated": True
            }
        },
        {
            "event_type": "command_blocked",
            "source": "command_collector",
            "severity": "high",
            "evidence": {
                "command": f"scan {random.choice(['.aws/credentials', '.env', 'id_ed25519', 'shadow'])}",
                "block_subtype": "security_scan_alert",
                "reason": "Sensitive key targeting",
                "is_simulated": True
            }
        }
    ]

    selected = random.choice(templates)
    ev = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),
        event_type=selected["event_type"],
        source=selected["source"],
        severity=selected["severity"],
        process_name=selected.get("process_name"),
        executable_path=selected.get("executable_path"),
        pid=selected.get("pid"),
        evidence=selected["evidence"],
        collection_status="collected",
        is_simulated=True
    )
    await monitoring_service._process_event_async(ev)

    return {
        "status": "success",
        "message": f"Randomized template event '{selected['event_type']}' generated.",
        "event_id": ev.event_id,
        "is_simulated": True
    }

@demo_router.post("/reset")
async def reset_demo_data(db: Session = Depends(get_db)):
    """Removes all simulated events and simulated incidents while preserving real data."""
    ev_count = db.query(EventModel).filter(EventModel.is_simulated == True).delete()
    inc_count = db.query(IncidentModel).filter(IncidentModel.is_simulated == True).delete()
    db.commit()

    await ws_manager.broadcast("demo_reset", {"cleared_events": ev_count, "cleared_incidents": inc_count})

    return {
        "message": f"Reset demo mode: removed {ev_count} simulated events and {inc_count} simulated incidents.",
        "cleared_events": ev_count,
        "cleared_incidents": inc_count
    }
