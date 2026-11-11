from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from app.detection.rules.base_rule import BaseRule, EvaluationResult
from app.schemas.event import NormalizedEvent
from app.config import settings

class FileBurstRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="RULE_FILE_BURST",
            rule_name="File Change Burst",
            description="Detects an anomalous volume of rapid file modifications or creations within a short time window.",
            severity="medium"
        )

    def evaluate(self, current_event: NormalizedEvent, recent_events: List[NormalizedEvent], context: Dict[str, Any]) -> Optional[EvaluationResult]:
        if not self.enabled:
            return None

        # Only trigger on file modification/creation events
        if not current_event.event_type.startswith("file_"):
            return None

        threshold = context.get("file_burst_threshold", settings.FILE_BURST_THRESHOLD)
        window_seconds = context.get("file_burst_window_seconds", settings.FILE_BURST_WINDOW_SECONDS)

        cutoff = current_event.timestamp - timedelta(seconds=window_seconds)

        # Count file events within time window
        burst_events = [
            e for e in recent_events
            if e.event_type.startswith("file_") and e.timestamp >= cutoff
        ]
        # Include current event if not already in recent_events
        if current_event not in burst_events:
            burst_events.append(current_event)

        if len(burst_events) >= threshold:
            changed_paths = list(set([e.relative_path for e in burst_events if e.relative_path]))[:10]
            return EvaluationResult(
                triggered=True,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                confidence=0.75,
                evidence_summary=f"Observed {len(burst_events)} filesystem modification events in {window_seconds}s (Threshold: {threshold}).",
                evidence_data={
                    "event_count": len(burst_events),
                    "window_seconds": window_seconds,
                    "threshold": threshold,
                    "sample_changed_paths": changed_paths,
                    "window_start": cutoff.isoformat(),
                    "window_end": current_event.timestamp.isoformat()
                },
                suggested_investigation="Review the modified files to check if automated builds, archive extractions, or untrusted bulk write operations occurred.",
                rationale="Sudden spikes in file writes indicate automated batch processing, compiler churn, or potential ransomware-like mass alterations."
            )

        return None

    def get_metadata(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "description": self.description,
            "severity": self.severity,
            "required_evidence": ["event_count", "window_seconds", "threshold", "sample_changed_paths"],
            "matching_conditions": "Count of filesystem events exceeding threshold within specified sliding seconds window.",
            "rationale": "High-velocity changes indicate automated batch behavior requiring verification.",
            "suggested_investigation": "Inspect touched files and process responsible for the high write volume.",
            "enabled": self.enabled
        }
