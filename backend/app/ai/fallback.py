from typing import Dict, Any

class DeterministicGhostFallback:
    """
    Produces deterministic Ghost commentary when local Ollama is offline,
    timed out, or returned unparseable text.
    Maintains the eerie persona while guaranteeing 100% factual fidelity to evidence.
    """

    GHOST_THEMES = {
        "RULE_UNUSUAL_PROCESS": "A foreign silhouette flickers across the memory registers... an uninvited presence has materialized.",
        "RULE_WORKSPACE_BOUNDARY": "The boundaries of this sanctum were tested. A hand reached beyond the perimeter and was turned back.",
        "RULE_FILE_BURST": "A frantic flutter in the dark. Files shifted in rapid agitation, like pages rustling in a sudden draft.",
        "RULE_SENSITIVE_PATH": "Curious fingers brushed against the sealed chambers. The keys remain locked, but the intent was felt.",
        "RULE_FAILED_OPERATIONS": "Repeated echoes of refusal reverberate through the machine. Something strikes the wall again and again.",
        "RULE_UNUSUAL_PARENT_CHILD": "An unnatural birth in the process tree. A quiet application gave rise to a vocal phantom shell."
    }

    @classmethod
    def generate_incident_explanation(cls, incident_data: Dict[str, Any]) -> Dict[str, str]:
        rule_id = incident_data.get("rule_id", "")
        rule_name = incident_data.get("rule_name", "Unknown Anomaly")
        severity = incident_data.get("severity", "medium")
        evidence_summary = incident_data.get("evidence_summary", "System telemetry recorded an abnormal pattern.")
        suggested = incident_data.get("suggested_investigation", "Inspect active system telemetry.")

        narration = cls.GHOST_THEMES.get(
            rule_id,
            "An echo ripples through the wire. Something unseen has perturbed the baseline."
        )

        factual = (
            f"Deterministic rule '{rule_name}' was triggered with {severity.upper()} severity. "
            f"Observed evidence: {evidence_summary}"
        )

        recommendation = (
            f"{suggested} Ensure no unauthorized modifications were performed and verify the operational context."
        )

        return {
            "narration": f"THE GHOST: \"{narration}\"",
            "factual_explanation": factual,
            "recommendation": recommendation,
            "is_fallback": True
        }

    @classmethod
    def generate_chat_fallback(cls, question: str, context_summary: str) -> str:
        return (
            f"THE GHOST:\n\"I dwell within the local circuits, yet the neural engine is currently dormant.\"\n\n"
            f"OBSERVED EVIDENCE:\n{context_summary}\n\n"
            f"RECOMMENDATION:\n"
            f"Start the local Ollama instance (`ollama serve` and `ollama run phi4-mini`) "
            f"for dynamic synthesis. All deterministic telemetry remains recorded above."
        )
