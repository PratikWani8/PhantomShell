from typing import Optional, Dict, Any, List
from app.detection.rules.base_rule import BaseRule, EvaluationResult
from app.schemas.event import NormalizedEvent
from app.config import settings

class UnusualProcessRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="RULE_UNUSUAL_PROCESS",
            rule_name="Unusual Process Appearance",
            description="Detects newly spawned processes matching known high-risk offensive security tools or suspicious execution patterns.",
            severity="high"
        )

    def evaluate(self, current_event: NormalizedEvent, recent_events: List[NormalizedEvent], context: Dict[str, Any]) -> Optional[EvaluationResult]:
        if not self.enabled:
            return None

        if current_event.event_type != "process_spawn":
            return None

        pname = (current_event.process_name or "").lower().strip()
        exe = (current_event.executable_path or "").lower().strip()
        if not pname:
            return None

        suspicious_list = [s.lower() for s in settings.SUSPICIOUS_PROCESS_NAMES]
        
        # Exact match or endswith on process name or exe basename
        matched_pattern = None
        for susp in suspicious_list:
            if pname == susp or pname.endswith(f"\\{susp}") or pname.endswith(f"/{susp}"):
                matched_pattern = susp
                break
            if exe and (exe.endswith(f"\\{susp}") or exe.endswith(f"/{susp}")):
                matched_pattern = susp
                break

        if matched_pattern:
            return EvaluationResult(
                triggered=True,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                confidence=0.90,
                evidence_summary=f"Spawned process '{current_event.process_name}' (PID: {current_event.pid}) matched flagged utility signature '{matched_pattern}'.",
                evidence_data={
                    "pid": current_event.pid,
                    "process_name": current_event.process_name,
                    "executable_path": current_event.executable_path,
                    "parent_pid": current_event.parent_pid,
                    "matched_pattern": matched_pattern,
                    "timestamp": current_event.timestamp.isoformat()
                },
                suggested_investigation="Verify whether this utility was intentionally executed by an authorized administrator. Inspect parent PID lineage.",
                rationale="Offensive tools like netcat or credential dumpers in standard workflows represent elevated operational risk."
            )

        return None

    def get_metadata(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "description": self.description,
            "severity": self.severity,
            "required_evidence": ["process_name", "pid", "executable_path"],
            "matching_conditions": "Process name or executable matches configured suspicious binaries allowlist/blocklist.",
            "rationale": "High-risk binaries require immediate contextual validation.",
            "suggested_investigation": "Check execution origin and parent process hierarchy.",
            "enabled": self.enabled
        }
