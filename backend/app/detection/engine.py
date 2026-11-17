import uuid
import time
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

from app.schemas.event import NormalizedEvent
from app.detection.rules.base_rule import BaseRule, EvaluationResult
from app.detection.rules.unusual_process import UnusualProcessRule
from app.detection.rules.workspace_boundary import WorkspaceBoundaryRule
from app.detection.rules.file_burst import FileBurstRule
from app.detection.rules.sensitive_path import SensitivePathRule
from app.detection.rules.failed_operations import RepeatedFailedOperationsRule
from app.detection.rules.parent_child import UnusualParentChildRule
from app.detection.scorer import RiskScorer

logger = logging.getLogger("phantomshell.detection.engine")

class DetectionEngine:
    def __init__(self):
        self.rules: List[BaseRule] = [
            UnusualProcessRule(),
            WorkspaceBoundaryRule(),
            FileBurstRule(),
            SensitivePathRule(),
            RepeatedFailedOperationsRule(),
            UnusualParentChildRule()
        ]
        self._recent_events: List[NormalizedEvent] = []
        self._max_recent_events = 200
        # Duplicate suppression tracking: key -> timestamp
        self._recent_incident_signatures: Dict[str, float] = {}
        self.suppression_cooldown_seconds = 10.0

    def get_rules_metadata(self) -> List[dict]:
        return [rule.get_metadata() for rule in self.rules]

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> bool:
        for r in self.rules:
            if r.rule_id == rule_id:
                r.enabled = enabled
                return True
        return False

    def evaluate_event(self, event: NormalizedEvent, context: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        Evaluates event against all rules.
        Returns list of newly triggered incident payloads (with duplicate suppression).
        """
        ctx = context or {}
        now = time.time()

        # Add event to recent memory
        self._recent_events.append(event)
        if len(self._recent_events) > self._max_recent_events:
            self._recent_events.pop(0)

        triggered_incidents = []

        for rule in self.rules:
            try:
                res: Optional[EvaluationResult] = rule.evaluate(
                    current_event=event,
                    recent_events=self._recent_events,
                    context=ctx
                )
                if not res or not res.triggered:
                    continue

                # Duplicate suppression check
                # Deduplicate by rule_id + key evidence item (e.g. process name or path)
                target_key = (
                    res.evidence_data.get("matched_pattern") or
                    res.evidence_data.get("process_name") or
                    res.evidence_data.get("matched_sensitive_token") or
                    res.evidence_data.get("command") or
                    rule.rule_id
                )
                sig = f"{rule.rule_id}::{target_key}"

                last_seen = self._recent_incident_signatures.get(sig, 0.0)
                if now - last_seen < self.suppression_cooldown_seconds:
                    logger.debug(f"Suppressed duplicate incident signature: {sig}")
                    continue

                self._recent_incident_signatures[sig] = now

                # Calculate deterministic risk score
                score, label, explanation = RiskScorer.calculate_score(
                    severity=res.severity,
                    confidence=res.confidence,
                    context_factors={"rule_id": rule.rule_id}
                )

                incident_id = str(uuid.uuid4())
                incident_data = {
                    "id": incident_id,
                    "created_at": datetime.utcnow(),
                    "updated_at": datetime.utcnow(),
                    "rule_id": res.rule_id,
                    "rule_name": res.rule_name,
                    "description": rule.description,
                    "severity": res.severity,
                    "risk_score": score,
                    "risk_label": label,
                    "confidence": res.confidence,
                    "evidence_summary": res.evidence_summary,
                    "evidence_data": {
                        **res.evidence_data,
                        "scoring_explanation": explanation,
                        "rationale": res.rationale
                    },
                    "suggested_investigation": res.suggested_investigation,
                    "ai_status": "pending",
                    "status": "open",
                    "is_simulated": event.is_simulated
                }
                triggered_incidents.append(incident_data)

            except Exception as e:
                logger.error(f"Error evaluating rule {rule.rule_id}: {e}")

        # Clean old suppression signatures
        cutoff = now - 60.0
        self._recent_incident_signatures = {
            k: v for k, v in self._recent_incident_signatures.items() if v >= cutoff
        }

        return triggered_incidents
