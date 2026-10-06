from pydantic import BaseModel, Field
from scoring.rules import RiskSeverity


class DetectedAnomaly(BaseModel):
    rule_id: str
    severity: RiskSeverity
    penalty: int
    title: str
    description: str
    recommendation: str


class StealthAssessment(BaseModel):
    stealth_score: int = Field(ge=0, le=100, description="Final masking score from 0% to 100%")
    status: str = Field(description="Verdict: UNDETECTED, SUSPICIOUS, BUSTED")
    total_penalties: int = Field(description="Sum of all penalties")
    critical_triggers_count: int = Field(default=0)
    anomalies: list[DetectedAnomaly] = Field(default_factory=list)