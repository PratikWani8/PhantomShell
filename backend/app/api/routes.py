import os
import json
import uuid
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.settings import SettingsModel
from app.models.event import EventModel
from app.models.incident import IncidentModel
from app.schemas.event import EventResponse, EventFilterParams
from app.schemas.incident import IncidentResponse, IncidentFilterParams, IncidentUpdateStatus
from app.schemas.rule import RuleDefinition
from app.schemas.monitoring import (
    MonitoringStatusResponse, DirectoryUpdateRequest, CollectorToggleRequest,
    TerminalCommandRequest, TerminalCommandResponse
)
from app.schemas.ai import (
    AIStatusResponse, AIExplanationResponse, AIChatRequest, AIChatResponse, SystemSummaryResponse
)
from app.schemas.settings import SettingsResponse, SettingsUpdateRequest
from app.services.monitoring_service import monitoring_service
from app.services.event_service import event_service
from app.services.incident_service import incident_service
from app.ai.ollama_client import ollama_client
from app.collectors.command_collector import CommandCollector
from app.config import settings

api_router = APIRouter(prefix="/api")

# =========================================================================
# Health & System Summary
# =========================================================================
@api_router.get("/health", tags=["System"])
async def get_health():
    ai_health = await ollama_client.check_health()
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "application": "PhantomShell",
        "version": "1.0.0",
        "local_ai_connected": ai_health["is_available"],
        "model": ai_health["model"]
    }

@api_router.get("/system/summary", response_model=SystemSummaryResponse, tags=["System"])
async def get_system_summary(db: Session = Depends(get_db)):
    total_events = db.query(EventModel).count()
    total_incidents = db.query(IncidentModel).count()
    open_incidents = db.query(IncidentModel).filter(IncidentModel.status == "open").count()
    highest_inc = db.query(IncidentModel).order_by(IncidentModel.risk_score.desc()).first()
    latest_narration_inc = db.query(IncidentModel).filter(IncidentModel.ai_narration != None).order_by(IncidentModel.created_at.desc()).first()

    ai_status = await ollama_client.check_health()
    mon_status = monitoring_service.get_status()

    return SystemSummaryResponse(
        total_events=total_events,
        total_incidents=total_incidents,
        open_incidents=open_incidents,
        highest_risk_score=highest_inc.risk_score if highest_inc else 0,
        highest_risk_label=highest_inc.risk_label if highest_inc else "None",
        monitoring_active=mon_status["is_active"],
        ai_available=ai_status["is_available"],
        active_monitored_directory=mon_status["monitored_directory"],
        latest_ghost_narration=latest_narration_inc.ai_narration if latest_narration_inc else "The void is quiet. Telemetry awaits observation."
    )

# =========================================================================
# Monitoring Lifecycle
# =========================================================================
@api_router.get("/monitoring/status", response_model=MonitoringStatusResponse, tags=["Monitoring"])
async def get_monitoring_status():
    return monitoring_service.get_status()

@api_router.post("/monitoring/start", tags=["Monitoring"])
async def start_monitoring():
    await monitoring_service.start()
    return {"message": "Monitoring activated successfully.", "status": monitoring_service.get_status()}

@api_router.post("/monitoring/stop", tags=["Monitoring"])
async def stop_monitoring():
    await monitoring_service.stop()
    return {"message": "Monitoring stopped successfully.", "status": monitoring_service.get_status()}

@api_router.post("/monitoring/pause", tags=["Monitoring"])
async def pause_monitoring():
    await monitoring_service.pause()
    return {"message": "Monitoring paused successfully.", "status": monitoring_service.get_status()}

@api_router.post("/monitoring/resume", tags=["Monitoring"])
async def resume_monitoring():
    await monitoring_service.resume()
    return {"message": "Monitoring resumed successfully.", "status": monitoring_service.get_status()}

@api_router.post("/monitoring/directory", tags=["Monitoring"])
async def update_monitored_directory(payload: DirectoryUpdateRequest):
    await monitoring_service.update_directory(payload.directory_path)
    return {"message": f"Monitored directory set to '{payload.directory_path}'", "status": monitoring_service.get_status()}

@api_router.post("/monitoring/collector/toggle", tags=["Monitoring"])
async def toggle_collector(payload: CollectorToggleRequest):
    success = await monitoring_service.toggle_collector(payload.collector_name, payload.enabled)
    if not success:
        raise HTTPException(status_code=404, detail=f"Collector '{payload.collector_name}' not found.")
    return {"message": f"Collector '{payload.collector_name}' enabled={payload.enabled}", "status": monitoring_service.get_status()}

# =========================================================================
# Application Terminal
# =========================================================================
@api_router.post("/terminal/execute", response_model=TerminalCommandResponse, tags=["Terminal"])
async def execute_terminal_command(payload: TerminalCommandRequest):
    cmd_collector = monitoring_service.collector_manager.collectors.get("command_collector")
    if not isinstance(cmd_collector, CommandCollector):
        raise HTTPException(status_code=500, detail="Command collector unavailable.")
    
    result = cmd_collector.execute_terminal_command(payload.command)
    return TerminalCommandResponse(**result)

# =========================================================================
# Events
# =========================================================================
@api_router.get("/events", tags=["Events"])
async def list_events(
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    search: Optional[str] = None,
    is_simulated: Optional[bool] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    params = EventFilterParams(
        event_type=event_type,
        severity=severity,
        source=source,
        search=search,
        is_simulated=is_simulated,
        limit=limit,
        offset=offset
    )
    events, total = event_service.get_events(db, params)
    return {"total": total, "events": events, "limit": limit, "offset": offset}

@api_router.get("/events/{event_id}", response_model=EventResponse, tags=["Events"])
async def get_event(event_id: str, db: Session = Depends(get_db)):
    event = event_service.get_event_by_id(db, event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found.")
    return event

@api_router.delete("/events", tags=["Events"])
async def clear_events(confirm: bool = Query(False), db: Session = Depends(get_db)):
    if not confirm:
        raise HTTPException(status_code=400, detail="Must set confirm=true to clear history.")
    deleted = event_service.clear_events(db)
    return {"message": f"Cleared {deleted} events.", "deleted_count": deleted}

# =========================================================================
# Incidents
# =========================================================================
@api_router.get("/incidents", tags=["Incidents"])
async def list_incidents(
    severity: Optional[str] = None,
    risk_label: Optional[str] = None,
    status: Optional[str] = None,
    rule_id: Optional[str] = None,
    is_simulated: Optional[bool] = None,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    params = IncidentFilterParams(
        severity=severity,
        risk_label=risk_label,
        status=status,
        rule_id=rule_id,
        is_simulated=is_simulated,
        limit=limit,
        offset=offset
    )
    incidents, total = incident_service.get_incidents(db, params)
    return {"total": total, "incidents": incidents, "limit": limit, "offset": offset}

@api_router.get("/incidents/{incident_id}", response_model=IncidentResponse, tags=["Incidents"])
async def get_incident(incident_id: str, db: Session = Depends(get_db)):
    inc = incident_service.get_incident_by_id(db, incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return inc

@api_router.patch("/incidents/{incident_id}/status", response_model=IncidentResponse, tags=["Incidents"])
async def update_incident_status(incident_id: str, payload: IncidentUpdateStatus, db: Session = Depends(get_db)):
    updated = await incident_service.update_status(db, incident_id, payload.status)
    if not updated:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return updated

@api_router.delete("/incidents", tags=["Incidents"])
async def clear_incidents(confirm: bool = Query(False), db: Session = Depends(get_db)):
    if not confirm:
        raise HTTPException(status_code=400, detail="Must set confirm=true to clear history.")
    deleted = incident_service.clear_incidents(db)
    return {"message": f"Cleared {deleted} incidents.", "deleted_count": deleted}

# =========================================================================
# Rules & Detection
# =========================================================================
@api_router.get("/rules", response_model=List[RuleDefinition], tags=["Rules"])
async def list_rules():
    return monitoring_service.detection_engine.get_rules_metadata()

@api_router.patch("/rules/{rule_id}", tags=["Rules"])
async def toggle_rule(rule_id: str, enabled: bool = Query(...)):
    success = monitoring_service.detection_engine.set_rule_enabled(rule_id, enabled)
    if not success:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found.")
    return {"message": f"Rule '{rule_id}' updated.", "rule_id": rule_id, "enabled": enabled}

# =========================================================================
# Local AI & Ghost Agent
# =========================================================================
@api_router.get("/ai/status", response_model=AIStatusResponse, tags=["AI"])
async def get_ai_status():
    return await ollama_client.check_health()

@api_router.post("/ai/explain/{incident_id}", response_model=AIExplanationResponse, tags=["AI"])
async def explain_incident(incident_id: str, db: Session = Depends(get_db)):
    inc = incident_service.get_incident_by_id(db, incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found.")
    
    explanation = await ollama_client.explain_incident(inc.model_dump(mode="json"))
    # Persist explanation if not previously populated
    db_inc = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
    if db_inc:
        db_inc.ai_narration = explanation["narration"]
        db_inc.ai_factual_explanation = explanation["factual_explanation"]
        db_inc.ai_recommendation = explanation["recommendation"]
        db_inc.ai_status = "completed" if not explanation["is_fallback"] else "fallback"
        db.commit()

    return AIExplanationResponse(**explanation)

@api_router.post("/ai/chat", response_model=AIChatResponse, tags=["AI"])
async def ai_chat(payload: AIChatRequest):
    result = await monitoring_service.ai_harness.process_user_query(
        user_question=payload.question,
        targeted_incident_id=payload.incident_id
    )
    return AIChatResponse(**result)

# =========================================================================
# Settings
# =========================================================================
@api_router.get("/settings", response_model=SettingsResponse, tags=["Settings"])
async def get_settings(db: Session = Depends(get_db)):
    cfg = db.query(SettingsModel).filter(SettingsModel.id == 1).first()
    if not cfg:
        cfg = SettingsModel(id=1)
        db.add(cfg)
        db.commit()
        db.refresh(cfg)
    return cfg

@api_router.patch("/settings", response_model=SettingsResponse, tags=["Settings"])
async def update_settings(payload: SettingsUpdateRequest, db: Session = Depends(get_db)):
    cfg = db.query(SettingsModel).filter(SettingsModel.id == 1).first()
    if not cfg:
        cfg = SettingsModel(id=1)
        db.add(cfg)

    updates = payload.model_dump(exclude_unset=True)
    for field, val in updates.items():
        setattr(cfg, field, val)

    db.commit()
    db.refresh(cfg)

    # Sync changes to active services
    if "monitored_dir" in updates and updates["monitored_dir"]:
        monitoring_service.collector_manager.update_monitored_directory(updates["monitored_dir"])
    if "ai_model" in updates and updates["ai_model"]:
        ollama_client.default_model = updates["ai_model"]

    return cfg
