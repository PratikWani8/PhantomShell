from typing import List
from pydantic import BaseModel, Field

class RuleDefinition(BaseModel):
    rule_id: str
    rule_name: str
    description: str
    severity: str
    required_evidence: List[str]
    matching_conditions: str
    rationale: str
    suggested_investigation: str
    enabled: bool = True
