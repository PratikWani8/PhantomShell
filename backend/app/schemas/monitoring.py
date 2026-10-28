from typing import Dict, Any, List
from pydantic import BaseModel, Field

class CollectorStatus(BaseModel):
    name: str
    enabled: bool
    running: bool
    events_collected: int
    last_event_time: str = "never"
    error_message: str = ""

class MonitoringStatusResponse(BaseModel):
    is_active: bool
    is_paused: bool
    monitored_directory: str
    collectors: Dict[str, CollectorStatus]
    total_events_captured: int
    active_incidents_count: int

class DirectoryUpdateRequest(BaseModel):
    directory_path: str = Field(..., min_length=1, max_length=500)

class CollectorToggleRequest(BaseModel):
    collector_name: str
    enabled: bool

class TerminalCommandRequest(BaseModel):
    command: str = Field(..., max_length=200)

class TerminalCommandResponse(BaseModel):
    command: str
    output: str
    exit_code: int
    error: str = ""
    event_id: str
    execution_time_ms: float
