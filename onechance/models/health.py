"""Health monitoring and autonomous recovery models."""

from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class InstanceStatus(str, Enum):
    """Lifecycle status of a protected service container/instance."""
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNHEALTHY = "UNHEALTHY"
    ISOLATED = "ISOLATED"
    RECOVERING = "RECOVERING"
    TERMINATED = "TERMINATED"


class IsolationState(str, Enum):
    """State of traffic routing relative to isolated instance."""
    NORMAL = "NORMAL"
    ISOLATING = "ISOLATING"
    REROUTED = "REROUTED"
    RESTORING = "RESTORING"


class ServiceHealth(BaseModel):
    """Aggregate health status of monitored backend services."""
    primary_instance_id: str = "target-instance-primary"
    primary_status: InstanceStatus = InstanceStatus.HEALTHY
    primary_url: str
    active_target_url: str
    backup_instances: List[str] = Field(default_factory=list)
    consecutive_failures: int = 0
    average_latency_ms: float = 0.0
    last_health_check_timestamp: float = 0.0
    isolation_state: IsolationState = IsolationState.NORMAL


class RecoveryEvent(BaseModel):
    """Event log describing an autonomous recovery lifecycle action."""
    event_id: str
    timestamp: float
    trigger_reason: str
    action: str  # "ISOLATE", "REROUTE", "SPAWN_REPLACEMENT", "VERIFY_HEALTH", "RESTORE"
    target_instance: str
    status: str  # "IN_PROGRESS", "SUCCESS", "FAILED"
    details: Optional[Dict[str, str]] = None
