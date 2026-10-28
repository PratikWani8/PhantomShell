import json
from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, Boolean, Text
from app.database.session import Base

class EventModel(Base):
    __tablename__ = "events"

    id = Column(String(64), primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    event_type = Column(String(50), nullable=False, index=True)
    source = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), default="info", index=True)
    
    # Process metadata (if available)
    pid = Column(Integer, nullable=True)
    process_name = Column(String(255), nullable=True)
    parent_pid = Column(Integer, nullable=True)
    executable_path = Column(String(500), nullable=True)

    # File metadata (if available)
    relative_path = Column(String(500), nullable=True)

    # Evidence details & raw normalized payload (JSON serialized)
    evidence_json = Column(Text, default="{}")
    
    collection_status = Column(String(30), default="collected")
    is_simulated = Column(Boolean, default=False, index=True)

    def get_evidence(self):
        try:
            return json.loads(self.evidence_json or "{}")
        except Exception:
            return {}

    def set_evidence(self, data: dict):
        self.evidence_json = json.dumps(data)
