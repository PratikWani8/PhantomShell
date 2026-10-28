from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field

class NormalizedEvent(BaseModel):
    event_id: str = Field(..., description="Unique event identifier")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_type: str = Field(..., description="E.g., process_spawn, file_modify, command_exec")
    source: str = Field(..., description="Collector name or simulated fixture")
    severity: str = Field(default="info", description="info, low, medium, high, critical")
    
    # Process attributes
    pid: Optional[int] = None
    process_name: Optional[str] = None
    parent_pid: Optional[int] = None
    executable_path: Optional[str] = None
    
    # File attributes
    relative_path: Optional[str] = None
    
    # Evidence & status
    evidence: Dict[str, Any] = Field(default_factory=dict)
    detection_rule_id: Optional[str] = None
    collection_status: str = Field(default="collected")
    is_simulated: bool = Field(default=False)

class EventResponse(BaseModel):
    id: str
    timestamp: datetime
    event_type: str
    source: str
    severity: str
    pid: Optional[int] = None
    process_name: Optional[str] = None
    parent_pid: Optional[int] = None
    executable_path: Optional[str] = None
    relative_path: Optional[str] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)
    collection_status: str
    is_simulated: bool

    class Config:
        from_attributes = True

class EventFilterParams(BaseModel):
    event_type: Optional[str] = None
    severity: Optional[str] = None
    source: Optional[str] = None
    search: Optional[str] = None
    is_simulated: Optional[bool] = None
    limit: int = 100
    offset: int = 0
