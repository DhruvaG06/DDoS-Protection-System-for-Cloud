"""Security Event telemetry models for OneChance Adaptive Defense System."""

import uuid
import time
from typing import List, Optional
from pydantic import BaseModel, Field

from onechance.models.decisions import ActionEnum, ThreatLevel


class SecurityEvent(BaseModel):
    """Structured security decision event for real-time monitoring and dashboard telemetry."""
    event_id: str = Field(default_factory=lambda: f"evt_{uuid.uuid4().hex[:12]}", description="Unique security event identifier")
    timestamp: float = Field(default_factory=time.time, description="POSIX timestamp of event generation")
    source: str = Field(..., description="Client IP address or source workload identifier")
    endpoint: str = Field(..., description="Target URI path or API endpoint requested")
    risk_score: float = Field(ge=0.0, le=100.0, description="Calculated 0-100 composite risk score")
    threat_level: ThreatLevel = Field(..., description="Categorical threat level (LOW, MEDIUM, HIGH)")
    decision: ActionEnum = Field(..., description="Adaptive defense policy decision (ALLOW, CHALLENGE, BLOCK)")
    action: str = Field(..., description="Specific mitigation action executed (e.g. forward, challenge_issued, temporary_block)")
    reasons: List[str] = Field(default_factory=list, description="Human-readable explainability factor list")
    attack_origin: Optional[str] = Field(default="external_internet", description="Inferred attack vector / origin (external_internet, internal_cloud_workload)")
    affected_service: Optional[str] = Field(default="gateway_ingress", description="Target application service or route affected")
    policy_version: str = Field(default="v3.0-adaptive-policy", description="Version of active policy engine")
