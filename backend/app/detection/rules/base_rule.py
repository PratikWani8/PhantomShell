import abc
from datetime import datetime
from typing import Optional, Dict, Any, List
from app.schemas.event import NormalizedEvent

class EvaluationResult:
    def __init__(
        self,
        triggered: bool,
        rule_id: str,
        rule_name: str,
        severity: str,
        confidence: float,
        evidence_summary: str,
        evidence_data: Dict[str, Any],
        suggested_investigation: str,
        rationale: str
    ):
        self.triggered = triggered
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.severity = severity
        self.confidence = confidence
        self.evidence_summary = evidence_summary
        self.evidence_data = evidence_data
        self.suggested_investigation = suggested_investigation
        self.rationale = rationale

class BaseRule(abc.ABC):
    def __init__(self, rule_id: str, rule_name: str, description: str, severity: str):
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.description = description
        self.severity = severity
        self.enabled = True

    @abc.abstractmethod
    def evaluate(self, current_event: NormalizedEvent, recent_events: List[NormalizedEvent], context: Dict[str, Any]) -> Optional[EvaluationResult]:
        """
        Evaluates current_event in the context of recent_events.
        Returns EvaluationResult if triggered, else None.
        """
        pass

    @abc.abstractmethod
    def get_metadata(self) -> dict:
        pass
