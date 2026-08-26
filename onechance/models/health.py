"""Health monitoring, Service Registry, and Autonomous Self-Healing Models (Phase 4)."""

from enum import Enum
import time
import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class InstanceStatus(str, Enum):
    """Lifecycle status of an individual application instance / container."""
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNHEALTHY = "UNHEALTHY"
    ISOLATED = "ISOLATED"
    STARTING = "STARTING"
    RECOVERING = "RECOVERING"
    TERMINATED = "TERMINATED"


class IsolationState(str, Enum):
    """Cluster-wide traffic routing state relative to isolated instances."""
    NORMAL = "NORMAL"
    ISOLATING = "ISOLATING"
    REROUTED = "REROUTED"
    RESTORING = "RESTORING"
    RECOVERED = "RECOVERED"


class InstanceRecord(BaseModel):
    """Detailed state record for an individual registered application instance."""
    instance_id: str = Field(..., description="Unique instance identifier (e.g., app-1, app-2)")
    container_name: str = Field(default="", description="Docker container or host name")
    url: str = Field(..., description="Base HTTP URL for accessing the instance")
    status: InstanceStatus = Field(default=InstanceStatus.HEALTHY, description="Current operational state")
    is_accepting_traffic: bool = Field(default=True, description="Whether the gateway forwards client traffic to this instance")
    last_health_check_timestamp: float = Field(default_factory=time.time, description="POSIX timestamp of last probe")
    last_status_code: int = Field(default=200, description="HTTP status code from last health check")
    consecutive_successes: int = Field(default=3, description="Count of consecutive successful health checks")
    consecutive_failures: int = Field(default=0, description="Count of consecutive failed health checks")
    average_latency_ms: float = Field(default=0.0, description="Recent average response latency in milliseconds")
    error_count: int = Field(default=0, description="Cumulative error count observed")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Instance metadata tags")


class RecoveryEventType(str, Enum):
    """Standardized Phase 4 Infrastructure and Self-Healing Event Types."""
    INSTANCE_UNHEALTHY = "INSTANCE_UNHEALTHY"
    INSTANCE_ISOLATED = "INSTANCE_ISOLATED"
    TRAFFIC_REROUTED = "TRAFFIC_REROUTED"
    REPLACEMENT_STARTED = "REPLACEMENT_STARTED"
    REPLACEMENT_HEALTHY = "REPLACEMENT_HEALTHY"
    INSTANCE_REINTRODUCED = "INSTANCE_REINTRODUCED"
    SERVICE_RECOVERY_VERIFIED = "SERVICE_RECOVERY_VERIFIED"


class RecoveryEvent(BaseModel):
    """Structured infrastructure recovery event for telemetry and dashboard observation."""
    event_id: str = Field(default_factory=lambda: f"rec_{uuid.uuid4().hex[:12]}", description="Unique recovery event ID")
    timestamp: float = Field(default_factory=time.time, description="POSIX timestamp of event generation")
    event_type: RecoveryEventType = Field(..., description="Specific phase in the recovery lifecycle")
    instance_id: str = Field(..., description="Affected application instance ID")
    status: str = Field(default="SUCCESS", description="Execution status (SUCCESS, IN_PROGRESS, FAILED)")
    trigger_reason: str = Field(..., description="Explainability reason for the recovery action")
    recovery_confidence: Optional[float] = Field(default=None, description="Recovery Confidence score (0.0 to 100.0) if verified")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Operational context metadata")

    @property
    def action(self) -> str:
        if self.event_type == RecoveryEventType.INSTANCE_ISOLATED:
            return "ISOLATE"
        return self.event_type.value

    @property
    def target_instance(self) -> str:
        return self.instance_id



class RecoveryVerificationMetrics(BaseModel):
    """Operational indicators used to compute Recovery Confidence."""
    recovery_confidence: float = Field(ge=0.0, le=100.0, description="Calculated 0-100 Recovery Confidence Score")
    healthy_instances_ratio: float = Field(..., description="Ratio of healthy active instances vs total expected capacity")
    health_probe_success_rate: float = Field(..., description="Success rate on recent health probes")
    latency_stability_score: float = Field(..., description="Latency stability index relative to baseline")
    error_rate_score: float = Field(..., description="Inverted recent error rate index")
    timestamp: float = Field(default_factory=time.time)
    verified_at: str = Field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))


class ClusterHealthSnapshot(BaseModel):
    """Aggregate health snapshot across all managed application instances."""
    cluster_status: str = Field(default="HEALTHY", description="Overall cluster status: HEALTHY, DEGRADED, RECOVERING")
    isolation_state: IsolationState = Field(default=IsolationState.NORMAL)
    total_instances_count: int = 0
    active_instances_count: int = 0
    healthy_instances_count: int = 0
    isolated_instances_count: int = 0
    instances: List[InstanceRecord] = Field(default_factory=list)
    recovery_confidence: float = 100.0
    last_updated: float = Field(default_factory=time.time)


class ServiceHealth(BaseModel):
    """Legacy/Single-instance health schema for backwards compatibility."""
    primary_instance_id: str = "app-1"
    primary_status: InstanceStatus = InstanceStatus.HEALTHY
    primary_url: str = "http://localhost:8001"
    active_target_url: str = "http://localhost:8001"
    backup_instances: List[str] = Field(default_factory=list)
    consecutive_failures: int = 0
    average_latency_ms: float = 0.0
    last_health_check_timestamp: float = 0.0
    isolation_state: IsolationState = IsolationState.NORMAL

