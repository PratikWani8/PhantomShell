from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class AIStatusResponse(BaseModel):
    is_available: bool
    model: str
    base_url: str
    latency_ms: Optional[float] = None
    installed_models: List[str] = Field(default_factory=list)
    error_message: Optional[str] = None

class AIExplanationResponse(BaseModel):
    incident_id: str
    narration: str
    factual_explanation: str
    recommendation: str
    is_fallback: bool
    model_used: str

class AIChatRequest(BaseModel):
    question: str = Field(..., min_length=2, max_length=500)
    incident_id: Optional[str] = None

class AIChatResponse(BaseModel):
    answer: str
    evidence_referenced: List[Dict[str, Any]] = Field(default_factory=list)
    is_fallback: bool
    model_used: str
    tool_calls: List[str] = Field(default_factory=list)

class SystemSummaryResponse(BaseModel):
    total_events: int
    total_incidents: int
    open_incidents: int
    highest_risk_score: int
    highest_risk_label: str
    monitoring_active: bool
    ai_available: bool
    active_monitored_directory: str
    latest_ghost_narration: str
