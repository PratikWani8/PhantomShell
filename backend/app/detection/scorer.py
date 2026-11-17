from typing import Dict, Any, Tuple

SEVERITY_WEIGHTS = {
    "info": 10,
    "low": 30,
    "medium": 60,
    "high": 85,
    "critical": 95
}

class RiskScorer:
    """
    Transparent, deterministic risk scoring engine.
    Calculates 0-100 score based purely on rule severity, evidence confidence, and context.
    """

    @staticmethod
    def calculate_score(
        severity: str,
        confidence: float,
        context_factors: Dict[str, Any] = None
    ) -> Tuple[int, str, Dict[str, Any]]:
        """
        Returns:
            (score, label, explanation_factors)
        """
        factors = context_factors or {}
        base_weight = SEVERITY_WEIGHTS.get(severity.lower(), 40)
        
        # Clamp confidence to [0.1, 1.0]
        conf = max(0.1, min(1.0, confidence))
        
        # Calculate raw score
        raw_score = base_weight * conf

        # Adjust for repeated occurrences if provided
        repeat_multiplier = factors.get("repeat_multiplier", 1.0)
        adjusted_score = raw_score * repeat_multiplier

        # Bound to integer 0 - 100
        final_score = int(max(0, min(100, round(adjusted_score))))

        # Determine label
        if final_score < 25:
            label = "Informational"
        elif final_score < 50:
            label = "Low"
        elif final_score < 75:
            label = "Medium"
        else:
            label = "High"

        explanation = {
            "base_severity_weight": base_weight,
            "evidence_confidence": round(conf, 2),
            "repeat_multiplier": round(repeat_multiplier, 2),
            "calculated_raw": round(raw_score, 1),
            "final_score": final_score,
            "assigned_label": label,
            "scoring_formula": "round(min(100, severity_weight * confidence * repeat_multiplier))"
        }

        return final_score, label, explanation
