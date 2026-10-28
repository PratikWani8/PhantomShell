from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field

class IncidentResponse(BaseModel):
    id: str
    created_at: datetime
    updated_at: datetime
    rule_id: str
    rule_name: str
    description: str
    severity: str
    risk_score: int
    risk_label: str
    confidence: float
    evidence_summary: str
    evidence_data: Dict[str, Any] = Field(default_factory=dict)
    suggested_investigation: str
    ai_narration: Optional[str] = None
    ai_factual_explanation: Optional[str] = None
    ai_recommendation: Optional[str] = None
    ai_status: str
    status: str
    is_simulated: bool

    class Config:
        from_attributes = True

class IncidentUpdateStatus(BaseModel):
    status: str = Field(..., pattern="^(open|acknowledged|dismissed)$")

class IncidentFilterParams(BaseModel):
    severity: Optional[str] = None
    risk_label: Optional[str] = None
    status: Optional[str] = None
    rule_id: Optional[str] = None
    is_simulated: Optional[bool] = None
    limit: int = 50
    offset: int = 0
