"""Risk scoring and policy decision models."""

from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class ActionEnum(str, Enum):
    """Three-tiered risk adaptive response actions."""
    ALLOW = "ALLOW"
    CHALLENGE = "CHALLENGE"
    BLOCK = "BLOCK"


class RiskAssessment(BaseModel):
    """Calculated risk score along with signal contributions."""
    client_ip: str
    risk_score: float = Field(ge=0.0, le=100.0, description="Risk score from 0 (benign) to 100 (critical)")
    anomaly_probability: float = Field(ge=0.0, le=1.0, description="ML anomaly probability score")
    signal_breakdown: Dict[str, float] = Field(default_factory=dict)
    contributing_reasons: List[str] = Field(default_factory=list)


class PolicyDecision(BaseModel):
    """Policy engine output determining response action."""
    action: ActionEnum
    client_ip: str
    risk_score: float
    reason: str
    challenge_token: Optional[str] = None
    block_duration_seconds: Optional[int] = None
