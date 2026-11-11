import time
import logging
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, ValidationError

from app.database.session import SessionLocal
from app.models.event import EventModel
from app.models.incident import IncidentModel
from app.ai.ollama_client import ollama_client
from app.security.sanitization import InputSanitizer

logger = logging.getLogger("phantomshell.ai.harness")

# ==========================================
# Tool Argument Validation Schemas
# ==========================================
class GetRecentEventsArgs(BaseModel):
    limit: int = Field(default=20, ge=1, le=100)

class GetIncidentDetailsArgs(BaseModel):
    incident_id: str = Field(..., min_length=1, max_length=64)

class ExplainIncidentArgs(BaseModel):
    incident_id: str = Field(..., min_length=1, max_length=64)

class AIHarness:
    """
    Constrained, transparent tool harness.
    Restricted strictly to five read-only tools.
    Zero filesystem writes, zero arbitrary execution, zero network access.
    """

    ALLOWED_TOOLS = {
        "get_recent_events",
        "get_incident_details",
        "get_active_rules",
        "get_system_summary",
        "explain_incident"
    }

    def __init__(self, detection_engine=None):
        self.detection_engine = detection_engine
        self.max_tool_calls_per_turn = 3

    # ==========================================
    # Tool 1: get_recent_events
    # ==========================================
    def get_recent_events(self, limit: int = 20) -> List[Dict[str, Any]]:
        db = SessionLocal()
        try:
            events = db.query(EventModel).order_by(EventModel.timestamp.desc()).limit(limit).all()
            return [
                {
                    "id": e.id,
                    "timestamp": e.timestamp.isoformat(),
                    "event_type": e.event_type,
                    "source": e.source,
                    "severity": e.severity,
                    "process_name": e.process_name,
                    "relative_path": e.relative_path,
                    "evidence": e.get_evidence(),
                    "is_simulated": e.is_simulated
                }
                for e in events
            ]
        finally:
            db.close()

    # ==========================================
    # Tool 2: get_incident_details
    # ==========================================
    def get_incident_details(self, incident_id: str) -> Optional[Dict[str, Any]]:
        db = SessionLocal()
        try:
            inc = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
            if not inc:
                return None
            return {
                "id": inc.id,
                "created_at": inc.created_at.isoformat(),
                "rule_id": inc.rule_id,
                "rule_name": inc.rule_name,
                "severity": inc.severity,
                "risk_score": inc.risk_score,
                "risk_label": inc.risk_label,
                "evidence_summary": inc.evidence_summary,
                "evidence_data": inc.get_evidence_data(),
                "suggested_investigation": inc.suggested_investigation,
                "ai_narration": inc.ai_narration,
                "ai_factual_explanation": inc.ai_factual_explanation,
                "status": inc.status,
                "is_simulated": inc.is_simulated
            }
        finally:
            db.close()

    # ==========================================
    # Tool 3: get_active_rules
    # ==========================================
    def get_active_rules(self) -> List[Dict[str, Any]]:
        if self.detection_engine:
            return self.detection_engine.get_rules_metadata()
        return []

    # ==========================================
    # Tool 4: get_system_summary
    # ==========================================
    def get_system_summary(self) -> Dict[str, Any]:
        db = SessionLocal()
        try:
            total_events = db.query(EventModel).count()
            total_incidents = db.query(IncidentModel).count()
            open_incidents = db.query(IncidentModel).filter(IncidentModel.status == "open").count()
            highest_inc = db.query(IncidentModel).order_by(IncidentModel.risk_score.desc()).first()

            return {
                "total_events": total_events,
                "total_incidents": total_incidents,
                "open_incidents": open_incidents,
                "highest_risk_score": highest_inc.risk_score if highest_inc else 0,
                "highest_risk_label": highest_inc.risk_label if highest_inc else "None",
                "highest_incident_id": highest_inc.id if highest_inc else None
            }
        finally:
            db.close()

    # ==========================================
    # Tool 5: explain_incident
    # ==========================================
    async def explain_incident(self, incident_id: str) -> Dict[str, Any]:
        inc_details = self.get_incident_details(incident_id)
        if not inc_details:
            return {"error": f"Incident '{incident_id}' not found."}
        return await ollama_client.explain_incident(inc_details)

    # ==========================================
    # Harness Execution Pipeline
    # ==========================================
    async def process_user_query(self, user_question: str, targeted_incident_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Coordinates context gathering via read-only tools and generates
        a grounded Ghost response.
        """
        tool_calls_made = []
        evidence_referenced = []
        context_parts = []

        # Step 1: If an incident ID is targeted, retrieve it directly
        if targeted_incident_id:
            tool_calls_made.append(f"get_incident_details({targeted_incident_id})")
            inc = self.get_incident_details(targeted_incident_id)
            if inc:
                evidence_referenced.append(inc)
                context_parts.append(
                    f"TARGET INCIDENT:\n"
                    f"ID: {inc['id']}\n"
                    f"Rule: {inc['rule_name']} ({inc['rule_id']})\n"
                    f"Severity: {inc['severity']} | Risk: {inc['risk_score']} ({inc['risk_label']})\n"
                    f"Evidence Summary: {inc['evidence_summary']}\n"
                    f"Suggested Investigation: {inc['suggested_investigation']}"
                )

        # Step 2: Retrieve system summary
        tool_calls_made.append("get_system_summary()")
        summary = self.get_system_summary()
        context_parts.append(
            f"SYSTEM SUMMARY:\n"
            f"Total events recorded: {summary['total_events']}\n"
            f"Total incidents: {summary['total_incidents']} (Open: {summary['open_incidents']})\n"
            f"Highest risk score: {summary['highest_risk_score']} ({summary['highest_risk_label']})"
        )

        # Step 3: Fetch recent events if question suggests timeline/event queries
        q_lower = user_question.lower()
        if any(w in q_lower for w in ["what happened", "events", "timeline", "recent", "process", "file", "activity"]):
            tool_calls_made.append("get_recent_events(limit=8)")
            events = self.get_recent_events(limit=8)
            formatted_events = [
                f"- [{e['timestamp'][:19]}] {e['event_type']} ({e['source']}): "
                f"{e.get('process_name') or e.get('relative_path') or e.get('evidence')}"
                for e in events
            ]
            context_parts.append("RECENT TELEMETRY EVENTS:\n" + "\n".join(formatted_events))
            evidence_referenced.extend(events[:3])

        # Step 4: If asking about rules
        if "rule" in q_lower:
            tool_calls_made.append("get_active_rules()")
            rules = self.get_active_rules()
            rule_names = [f"- {r['rule_name']} ({r['rule_id']}): {r['description']}" for r in rules]
            context_parts.append("ACTIVE DETECTION RULES:\n" + "\n".join(rule_names))

        compiled_context = "\n\n".join(context_parts)

        # Step 5: Query Ollama with compiled grounded context
        chat_res = await ollama_client.chat(
            question=user_question,
            context_summary=compiled_context
        )

        return {
            "answer": chat_res["answer"],
            "evidence_referenced": evidence_referenced,
            "is_fallback": chat_res["is_fallback"],
            "model_used": chat_res["model_used"],
            "tool_calls": tool_calls_made
        }
