from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from app.detection.rules.base_rule import BaseRule, EvaluationResult
from app.schemas.event import NormalizedEvent
from app.config import settings

class RepeatedFailedOperationsRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="RULE_FAILED_OPERATIONS",
            rule_name="Repeated Failed Operation",
            description="Detects multiple blocked or failed security operations within a short observation window.",
            severity="medium"
        )

    def evaluate(self, current_event: NormalizedEvent, recent_events: List[NormalizedEvent], context: Dict[str, Any]) -> Optional[EvaluationResult]:
        if not self.enabled:
            return None

        # Check if current event is a failed or blocked operation
        is_failure = (
            current_event.event_type == "command_blocked" or 
            (current_event.event_type == "command_exec" and current_event.evidence.get("exit_code", 0) != 0)
        )
        if not is_failure:
            return None

        threshold = context.get("failed_op_threshold", settings.FAILED_OP_THRESHOLD)
        window_seconds = context.get("failed_op_window_seconds", settings.FAILED_OP_WINDOW_SECONDS)

        cutoff = current_event.timestamp - timedelta(seconds=window_seconds)

        failed_events = [
            e for e in recent_events
            if (e.event_type == "command_blocked" or 
                (e.event_type == "command_exec" and e.evidence.get("exit_code", 0) != 0))
            and e.timestamp >= cutoff
        ]
        if current_event not in failed_events:
            failed_events.append(current_event)

        if len(failed_events) >= threshold:
            reasons = [e.evidence.get("reason", e.evidence.get("command", "Unknown error")) for e in failed_events]
            return EvaluationResult(
                triggered=True,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                confidence=0.82,
                evidence_summary=f"Detected {len(failed_events)} consecutive blocked/failed actions within {window_seconds}s (Threshold: {threshold}).",
                evidence_data={
                    "failed_count": len(failed_events),
                    "window_seconds": window_seconds,
                    "threshold": threshold,
                    "recent_reasons": reasons[-5:],
                    "timestamp": current_event.timestamp.isoformat()
                },
                suggested_investigation="Check if an operator or automated script is probing commands or brute-forcing invalid parameters.",
                rationale="Repeated failures indicate reconnaissance, misconfiguration, or interactive probe attempts."
            )

        return None

    def get_metadata(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "description": self.description,
            "severity": self.severity,
            "required_evidence": ["failed_count", "window_seconds", "threshold"],
            "matching_conditions": "Count of blocked or failing operations exceeds threshold within window.",
            "rationale": "Mitigates discovery attacks and repeated access violations.",
            "suggested_investigation": "Inspect terminal activity logs and source entity.",
            "enabled": self.enabled
        }
