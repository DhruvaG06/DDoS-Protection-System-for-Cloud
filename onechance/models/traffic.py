"""Traffic logging models and structured telemetry records."""

from enum import Enum
from typing import Dict, Optional
from pydantic import BaseModel, Field


class AttackSourceType(str, Enum):
    """Source classification for traffic / attack origins."""
    EXTERNAL = "external"
    INTERNAL_COMPROMISED = "internal_compromised"
    UNKNOWN = "unknown"


class TrafficRecord(BaseModel):
    """Structured traffic log record capturing essential telemetry for every request."""
    request_id: str = Field(..., description="Unique identifier for the request")
    timestamp: float = Field(..., description="Unix epoch timestamp when the request arrived")
    source: str = Field(..., description="Source identifier / client IP")
    method: str = Field(..., description="HTTP Method (GET, POST, etc.)")
    endpoint: str = Field(..., description="Target endpoint path")
    user_agent: Optional[str] = Field(default=None, description="Client User-Agent header")
    status_code: int = Field(..., description="HTTP Response status code")
    latency_ms: float = Field(..., description="Total roundtrip request duration in milliseconds")


class IncomingRequest(BaseModel):
    """Metadata representing an incoming HTTP request intercepted by the gateway."""
    client_ip: str
    method: str
    path: str
    headers: Dict[str, str] = Field(default_factory=dict)
    user_agent: Optional[str] = None
    timestamp: float
    source_type: AttackSourceType = AttackSourceType.EXTERNAL


class TrafficFeatures(BaseModel):
    """Extracted behavioral telemetry features over a sliding window."""
    client_ip: str
    request_rate_per_sec: float = 0.0
    endpoint_entropy: float = 0.0
    burstiness_score: float = 0.0
    error_rate: float = 0.0
    repeated_pattern_score: float = 0.0
    source_type: AttackSourceType = AttackSourceType.EXTERNAL
    window_duration_seconds: float = 10.0


class TrafficLog(BaseModel):
    """Logged event representing an inspected request and the action taken."""
    log_id: str
    timestamp: float
    client_ip: str
    method: str
    path: str
    source_type: AttackSourceType
    features: Optional[TrafficFeatures] = None
    risk_score: float = 0.0
    action: str = "ALLOW"
    latency_ms: float = 0.0
