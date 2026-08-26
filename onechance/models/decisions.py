"""Risk scoring and policy decision models."""

from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


from onechance.models.traffic import TrafficFeatures


class ActionEnum(str, Enum):
    """Three-tiered risk adaptive response actions."""
    ALLOW = "ALLOW"
    CHALLENGE = "CHALLENGE"
    BLOCK = "BLOCK"


class ThreatLevel(str, Enum):
    """Phase 2 normalized threat levels."""
    LOW = "LOW"        # Risk score 0 - 39
    MEDIUM = "MEDIUM"  # Risk score 40 - 69
    HIGH = "HIGH"      # Risk score 70 - 100


class RiskAssessment(BaseModel):
    """Calculated risk score along with signal contributions, features, and explainability."""
    client_ip: str
    risk_score: float = Field(ge=0.0, le=100.0, description="Normalized Risk score from 0 (benign) to 100 (critical)")
    threat_level: ThreatLevel = Field(default=ThreatLevel.LOW, description="Categorical threat level (LOW, MEDIUM, HIGH)")
    anomaly_probability: float = Field(ge=0.0, le=1.0, description="ML / behavioral anomaly probability score (0.0 to 1.0)")
    features: Optional[TrafficFeatures] = Field(default=None, description="Extracted 10-signal traffic features")
    signal_breakdown: Dict[str, float] = Field(default_factory=dict, description="Detailed per-signal score contributions")
    contributing_reasons: List[str] = Field(default_factory=list, description="Human-readable explainability reasons")
    detector_version: str = Field(default="v2.0-hybrid-rf", description="Version of the active detection engine")


class PolicyDecision(BaseModel):
    """Policy engine output determining response action."""
    action: ActionEnum
    client_ip: str
    risk_score: float
    reason: str
    challenge_token: Optional[str] = None
    block_duration_seconds: Optional[int] = None
