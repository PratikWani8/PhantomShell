from typing import Optional, Dict, Any, List
from app.detection.rules.base_rule import BaseRule, EvaluationResult
from app.schemas.event import NormalizedEvent

SUSPICIOUS_PARENTS = {
    "winword.exe": ["cmd.exe", "powershell.exe", "powershell_ise.exe", "wscript.exe", "cscript.exe", "bash.exe"],
    "excel.exe": ["cmd.exe", "powershell.exe", "powershell_ise.exe", "wscript.exe", "cscript.exe", "bash.exe"],
    "powerpnt.exe": ["cmd.exe", "powershell.exe", "powershell_ise.exe"],
    "outlook.exe": ["cmd.exe", "powershell.exe", "powershell_ise.exe", "wscript.exe", "cscript.exe"],
    "chrome.exe": ["powershell.exe", "cmd.exe", "nc.exe"],
    "msedge.exe": ["powershell.exe", "cmd.exe", "nc.exe"],
    "firefox.exe": ["powershell.exe", "cmd.exe", "nc.exe"],
}

class UnusualParentChildRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="RULE_UNUSUAL_PARENT_CHILD",
            rule_name="Unusual Parent-Child Relationship",
            description="Detects anomalous process spawning lineage where productivity or browser applications spawn command shells.",
            severity="high"
        )

    def evaluate(self, current_event: NormalizedEvent, recent_events: List[NormalizedEvent], context: Dict[str, Any]) -> Optional[EvaluationResult]:
        if not self.enabled:
            return None

        if current_event.event_type != "process_spawn":
            return None

        child_name = (current_event.process_name or "").lower().strip()
        evidence_parent = current_event.evidence.get("parent_process_name", "").lower().strip()
        
        # If parent_process_name not in evidence, check if parent_pid matches any known recent process in recent_events
        if not evidence_parent and current_event.parent_pid:
            for past in recent_events:
                if past.pid == current_event.parent_pid and past.process_name:
                    evidence_parent = past.process_name.lower().strip()
                    break

        if not evidence_parent:
            return None

        for susp_parent, forbidden_children in SUSPICIOUS_PARENTS.items():
            if susp_parent in evidence_parent:
                for target_child in forbidden_children:
                    if child_name == target_child or child_name.endswith(f"\\{target_child}"):
                        return EvaluationResult(
                            triggered=True,
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            severity=self.severity,
                            confidence=0.92,
                            evidence_summary=f"Suspicious lineage: '{evidence_parent}' (PID: {current_event.parent_pid}) spawned interactive shell '{current_event.process_name}' (PID: {current_event.pid}).",
                            evidence_data={
                                "parent_name": evidence_parent,
                                "parent_pid": current_event.parent_pid,
                                "child_name": current_event.process_name,
                                "child_pid": current_event.pid,
                                "executable_path": current_event.executable_path,
                                "timestamp": current_event.timestamp.isoformat()
                            },
                            suggested_investigation="Investigate whether this was triggered by macro execution, an exploited browser tab, or malicious document attachment.",
                            rationale="Standard office applications and web browsers typically do not spawn interactive shells during normal operation."
                        )

        return None

    def get_metadata(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "description": self.description,
            "severity": self.severity,
            "required_evidence": ["parent_name", "child_name", "parent_pid", "child_pid"],
            "matching_conditions": "Office application or browser spawns a shell or scripting host process.",
            "rationale": "Conservative detection of weaponized document or drive-by shell spawning.",
            "suggested_investigation": "Trace parent process command line and active user context.",
            "enabled": self.enabled
        }
