from typing import Optional, Dict, Any, List
from app.detection.rules.base_rule import BaseRule, EvaluationResult
from app.schemas.event import NormalizedEvent
from app.security.path_validator import PathValidator
from app.config import settings

class SensitivePathRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="RULE_SENSITIVE_PATH",
            rule_name="Sensitive Path Attempt",
            description="Detects an operation attempting to target credential stores, private keys, or system configuration paths.",
            severity="high"
        )

    def evaluate(self, current_event: NormalizedEvent, recent_events: List[NormalizedEvent], context: Dict[str, Any]) -> Optional[EvaluationResult]:
        if not self.enabled:
            return None

        target_path = None
        # Check command events
        if current_event.event_type in ("command_exec", "command_blocked"):
            cmd = current_event.evidence.get("command", "")
            for pattern in settings.SENSITIVE_PATHS:
                if pattern.lower() in cmd.lower():
                    target_path = pattern
                    break

        # Check file events
        if not target_path and current_event.relative_path:
            is_sens, pat = PathValidator.is_sensitive_path(current_event.relative_path, settings.SENSITIVE_PATHS)
            if is_sens:
                target_path = pat

        if target_path:
            return EvaluationResult(
                triggered=True,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                confidence=0.88,
                evidence_summary=f"Operation targeted protected sensitive resource path containing '{target_path}'.",
                evidence_data={
                    "event_type": current_event.event_type,
                    "matched_sensitive_token": target_path,
                    "relative_path": current_event.relative_path,
                    "command": current_event.evidence.get("command"),
                    "timestamp": current_event.timestamp.isoformat()
                },
                suggested_investigation="Audit whether private credentials or sensitive secrets were exposed or accessed intentionally.",
                rationale="Sensitive files (.ssh, .env, private keys) require strict access containment."
            )

        return None

    def get_metadata(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "description": self.description,
            "severity": self.severity,
            "required_evidence": ["matched_sensitive_token", "event_type"],
            "matching_conditions": "Target path or command targets sensitive credentials, private keys, or env files.",
            "rationale": "Protects local secrets from discovery or unintended exposure.",
            "suggested_investigation": "Inspect target path, calling process, and user intent.",
            "enabled": self.enabled
        }
