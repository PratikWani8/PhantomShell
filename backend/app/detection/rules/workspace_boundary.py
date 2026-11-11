from typing import Optional, Dict, Any, List
from app.detection.rules.base_rule import BaseRule, EvaluationResult
from app.schemas.event import NormalizedEvent

class WorkspaceBoundaryRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="RULE_WORKSPACE_BOUNDARY",
            rule_name="Workspace Boundary Violation",
            description="Detects an application operation actively attempting to access, read, or traverse outside the permitted workspace directory.",
            severity="medium"
        )

    def evaluate(self, current_event: NormalizedEvent, recent_events: List[NormalizedEvent], context: Dict[str, Any]) -> Optional[EvaluationResult]:
        if not self.enabled:
            return None

        # Check for blocked command events or boundary violation metadata
        if current_event.event_type == "command_blocked":
            subtype = current_event.evidence.get("block_subtype")
            if subtype in ("boundary_violation_attempt", "security_scan_alert"):
                cmd = current_event.evidence.get("command", "")
                reason = current_event.evidence.get("reason", "Out of bounds path traversal attempted")
                return EvaluationResult(
                    triggered=True,
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    confidence=0.95,
                    evidence_summary=f"Terminal operation attempted to traverse outside configured workspace. Command: '{cmd}'. Reason: {reason}",
                    evidence_data={
                        "event_id": current_event.event_id,
                        "command": cmd,
                        "violation_details": reason,
                        "timestamp": current_event.timestamp.isoformat()
                    },
                    suggested_investigation="Review the issued terminal command to see if the operator attempted directory traversal (e.g. '../') or absolute path escape.",
                    rationale="Applications must strictly constrain their operations to authorized directories."
                )

        return None

    def get_metadata(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "description": self.description,
            "severity": self.severity,
            "required_evidence": ["command", "block_subtype", "reason"],
            "matching_conditions": "Application operation attempts to resolve or traverse beyond designated sandbox boundary.",
            "rationale": "Prevents unauthorized directory traversal and workspace containment escapes.",
            "suggested_investigation": "Verify command arguments for path escape tokens like '..' or system root.",
            "enabled": self.enabled
        }
