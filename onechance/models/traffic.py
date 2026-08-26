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
    status_code: int = 200
    latency_ms: float = 0.0
    source_type: AttackSourceType = AttackSourceType.EXTERNAL


class TrafficFeatures(BaseModel):
    """Extracted behavioral telemetry features over a sliding window (Phase 2)."""
    client_ip: str
    requests_per_source: int = Field(default=0, description="1. Total requests from client IP in window")
    request_rate_per_sec: float = Field(default=0.0, description="2. Average request rate per second")
    endpoint_concentration: float = Field(default=0.0, description="3. Max ratio of requests to a single endpoint (0.0 - 1.0)")
    burstiness_score: float = Field(default=0.0, description="4. Peak 1-sec request rate vs window average rate")
    repeated_pattern_score: float = Field(default=0.0, description="5. Sequential identical endpoint repetition score (0.0 - 1.0)")
    source_distribution_ratio: float = Field(default=0.0, description="6. Client request volume relative to total window traffic (0.0 - 1.0)")
    endpoint_distribution_ratio: float = Field(default=0.0, description="7. Ratio of unique endpoints accessed vs total requests (0.0 - 1.0)")
    endpoint_entropy: float = Field(default=0.0, description="8. Shannon entropy over endpoint access frequency")
    error_ratio: float = Field(default=0.0, description="9. Ratio of 4xx/5xx HTTP errors in window (0.0 - 1.0)")
    average_latency_ms: float = Field(default=0.0, description="10. Average request roundtrip latency in milliseconds")
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
