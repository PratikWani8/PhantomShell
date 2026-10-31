import json
import logging
from typing import List, Optional, Tuple, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.incident import IncidentModel
from app.schemas.incident import IncidentResponse, IncidentFilterParams
from app.ai.ollama_client import ollama_client
from app.websocket.connection_manager import ws_manager

logger = logging.getLogger("phantomshell.services.incident")

class IncidentService:
    def __init__(self):
        pass

    async def create_incident(self, incident_data: Dict[str, Any], db: Session) -> IncidentModel:
        db_incident = IncidentModel(
            id=incident_data["id"],
            created_at=incident_data.get("created_at"),
            rule_id=incident_data["rule_id"],
            rule_name=incident_data["rule_name"],
            description=incident_data["description"],
            severity=incident_data["severity"],
            risk_score=incident_data["risk_score"],
            risk_label=incident_data["risk_label"],
            confidence=incident_data["confidence"],
            evidence_summary=incident_data["evidence_summary"],
            evidence_data_json=json.dumps(incident_data.get("evidence_data", {})),
            suggested_investigation=incident_data["suggested_investigation"],
            ai_status="pending",
            status="open",
            is_simulated=incident_data.get("is_simulated", False)
        )
        db.add(db_incident)
        db.commit()
        db.refresh(db_incident)

        # Broadcast initial incident detection over WebSocket
        await ws_manager.broadcast("incident", self._serialize_incident(db_incident))

        # Request AI explanation in background
        try:
            explanation = await ollama_client.explain_incident(incident_data)
            db_incident.ai_narration = explanation.get("narration")
            db_incident.ai_factual_explanation = explanation.get("factual_explanation")
            db_incident.ai_recommendation = explanation.get("recommendation")
            db_incident.ai_status = "fallback" if explanation.get("is_fallback") else "completed"
            db.commit()
            db.refresh(db_incident)

            # Broadcast updated incident with AI commentary
            await ws_manager.broadcast("incident_explained", self._serialize_incident(db_incident))
        except Exception as e:
            logger.error(f"Error fetching AI explanation for incident {db_incident.id}: {e}")
            db_incident.ai_status = "failed"
            db.commit()

        return db_incident

    def get_incidents(self, db: Session, params: IncidentFilterParams) -> Tuple[List[IncidentResponse], int]:
        query = db.query(IncidentModel)

        if params.severity:
            query = query.filter(IncidentModel.severity == params.severity)
        if params.risk_label:
            query = query.filter(IncidentModel.risk_label == params.risk_label)
        if params.status:
            query = query.filter(IncidentModel.status == params.status)
        if params.rule_id:
            query = query.filter(IncidentModel.rule_id == params.rule_id)
        if params.is_simulated is not None:
            query = query.filter(IncidentModel.is_simulated == params.is_simulated)

        total = query.count()
        incidents = query.order_by(desc(IncidentModel.created_at)).offset(params.offset).limit(params.limit).all()

        responses = [
            IncidentResponse(
                id=inc.id,
                created_at=inc.created_at,
                updated_at=inc.updated_at,
                rule_id=inc.rule_id,
                rule_name=inc.rule_name,
                description=inc.description,
                severity=inc.severity,
                risk_score=inc.risk_score,
                risk_label=inc.risk_label,
                confidence=inc.confidence,
                evidence_summary=inc.evidence_summary,
                evidence_data=inc.get_evidence_data(),
                suggested_investigation=inc.suggested_investigation,
                ai_narration=inc.ai_narration,
                ai_factual_explanation=inc.ai_factual_explanation,
                ai_recommendation=inc.ai_recommendation,
                ai_status=inc.ai_status,
                status=inc.status,
                is_simulated=inc.is_simulated
            )
            for inc in incidents
        ]
        return responses, total

    def get_incident_by_id(self, db: Session, incident_id: str) -> Optional[IncidentResponse]:
        inc = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
        if not inc:
            return None
        return IncidentResponse(
            id=inc.id,
            created_at=inc.created_at,
            updated_at=inc.updated_at,
            rule_id=inc.rule_id,
            rule_name=inc.rule_name,
            description=inc.description,
            severity=inc.severity,
            risk_score=inc.risk_score,
            risk_label=inc.risk_label,
            confidence=inc.confidence,
            evidence_summary=inc.evidence_summary,
            evidence_data=inc.get_evidence_data(),
            suggested_investigation=inc.suggested_investigation,
            ai_narration=inc.ai_narration,
            ai_factual_explanation=inc.ai_factual_explanation,
            ai_recommendation=inc.ai_recommendation,
            ai_status=inc.ai_status,
            status=inc.status,
            is_simulated=inc.is_simulated
        )

    async def update_status(self, db: Session, incident_id: str, new_status: str) -> Optional[IncidentResponse]:
        inc = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
        if not inc:
            return None
        inc.status = new_status
        db.commit()
        db.refresh(inc)

        resp = self.get_incident_by_id(db, incident_id)
        if resp:
            await ws_manager.broadcast("incident_status_change", resp.model_dump(mode="json"))
        return resp

    def clear_incidents(self, db: Session) -> int:
        count = db.query(IncidentModel).delete()
        db.commit()
        return count

    def _serialize_incident(self, inc: IncidentModel) -> dict:
        return {
            "id": inc.id,
            "created_at": inc.created_at.isoformat(),
            "updated_at": inc.updated_at.isoformat() if inc.updated_at else None,
            "rule_id": inc.rule_id,
            "rule_name": inc.rule_name,
            "description": inc.description,
            "severity": inc.severity,
            "risk_score": inc.risk_score,
            "risk_label": inc.risk_label,
            "confidence": inc.confidence,
            "evidence_summary": inc.evidence_summary,
            "evidence_data": inc.get_evidence_data(),
            "suggested_investigation": inc.suggested_investigation,
            "ai_narration": inc.ai_narration,
            "ai_factual_explanation": inc.ai_factual_explanation,
            "ai_recommendation": inc.ai_recommendation,
            "ai_status": inc.ai_status,
            "status": inc.status,
            "is_simulated": inc.is_simulated
        }

incident_service = IncidentService()
