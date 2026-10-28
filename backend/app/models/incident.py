import json
from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, DateTime, Boolean, Text
from app.database.session import Base

class IncidentModel(Base):
    __tablename__ = "incidents"

    id = Column(String(64), primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    rule_id = Column(String(100), nullable=False, index=True)
    rule_name = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), default="medium", index=True)

    # Risk scoring
    risk_score = Column(Integer, default=50) # 0 to 100
    risk_label = Column(String(30), default="Medium") # Informational, Low, Medium, High
    confidence = Column(Float, default=0.8) # 0.0 to 1.0

    evidence_summary = Column(Text, nullable=False)
    evidence_data_json = Column(Text, default="{}")
    suggested_investigation = Column(Text, nullable=False)

    # Ghost AI commentary
    ai_narration = Column(Text, nullable=True) # Eerie narration
    ai_factual_explanation = Column(Text, nullable=True) # Factual explanation
    ai_recommendation = Column(Text, nullable=True)
    ai_status = Column(String(30), default="pending") # pending, completed, fallback, failed

    # Incident state
    status = Column(String(20), default="open", index=True) # open, acknowledged, dismissed
    is_simulated = Column(Boolean, default=False, index=True)

    def get_evidence_data(self):
        try:
            return json.loads(self.evidence_data_json or "{}")
        except Exception:
            return {}

    def set_evidence_data(self, data: dict):
        self.evidence_data_json = json.dumps(data)
