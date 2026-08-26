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


from pydantic import BaseModel, Field, model_validator


class PolicyDecision(BaseModel):
    """Policy engine output determining response action and mitigation metadata."""
    decision: ActionEnum = Field(default=ActionEnum.ALLOW, description="Primary policy decision (ALLOW, CHALLENGE, BLOCK)")
    action: ActionEnum = Field(default=ActionEnum.ALLOW, description="Legacy alias for decision")
    client_ip: str = Field(..., description="Client IP address or source")
    endpoint: str = Field(default="/", description="Target URI path or route")
    risk_score: float = Field(ge=0.0, le=100.0, description="Composite risk score evaluated")
    threat_level: ThreatLevel = Field(default=ThreatLevel.LOW, description="Categorical threat level")
    action_type: str = Field(default="forward", description="Specific action executed (e.g. forward, challenge_issued, temporary_block)")
    reason: str = Field(..., description="Primary decision summary explanation")
    reasons: List[str] = Field(default_factory=list, description="Human-readable explainability factor list")
    challenge_token: Optional[str] = Field(default=None, description="Active challenge verification token if issued")
    block_duration_seconds: Optional[int] = Field(default=None, description="Duration in seconds if temporary block enforced")
    policy_version: str = Field(default="v3.0-adaptive-policy", description="Active policy engine version")

    @model_validator(mode="before")
    @classmethod
    def sync_decision_and_action(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "action" in data and "decision" not in data:
                data["decision"] = data["action"]
            elif "decision" in data and "action" not in data:
                data["action"] = data["decision"]
        return data
