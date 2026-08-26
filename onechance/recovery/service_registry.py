"""Service Registry & Instance State Management (Phase 4).

Tracks all application container instances, their operational states, health metrics,
and manages active traffic routing pools for the reverse proxy.
"""

import logging
import time
from typing import Dict, List, Optional
from onechance.models.health import (
    ClusterHealthSnapshot,
    InstanceRecord,
    InstanceStatus,
    IsolationState,
)

logger = logging.getLogger("onechance.service_registry")


class ServiceRegistry:
    """In-memory service registry managing multi-instance states and routing pools."""

    def __init__(self, init_defaults: bool = True):
        # instance_id -> InstanceRecord
        self._instances: Dict[str, InstanceRecord] = {}
        self._round_robin_index: int = 0
        self._isolation_state: IsolationState = IsolationState.NORMAL

        if init_defaults:
            try:
                from onechance.config import settings
                for instance_id, url in settings.get_target_instance_configs():
                    self.register_instance(
                        instance_id=instance_id,
                        url=url,
                        container_name=f"onechance-{instance_id}",
                    )
            except Exception as e:
                logger.warning(f"Could not load default instance configs: {e}")

    def register_instance(
        self,
        instance_id: str,
        url: str,
        container_name: Optional[str] = None,
        status: InstanceStatus = InstanceStatus.HEALTHY,
        is_accepting_traffic: bool = True,
    ) -> InstanceRecord:
        """Register or update an application instance in the registry."""
        clean_url = url.rstrip("/")
        record = InstanceRecord(
            instance_id=instance_id,
            container_name=container_name or instance_id,
            url=clean_url,
            status=status,
            is_accepting_traffic=is_accepting_traffic,
            last_health_check_timestamp=time.time(),
            consecutive_successes=3 if status == InstanceStatus.HEALTHY else 0,
            consecutive_failures=0 if status == InstanceStatus.HEALTHY else 1,
        )
        self._instances[instance_id] = record
        logger.info(f"Registered instance: {instance_id} at {clean_url} [status={status.value}, accepting_traffic={is_accepting_traffic}]")
        return record

    def get_instance(self, instance_id: str) -> Optional[InstanceRecord]:
        """Retrieve a specific instance record."""
        return self._instances.get(instance_id)

    def get_all_instances(self) -> List[InstanceRecord]:
        """Return list of all registered instances."""
        return list(self._instances.values())

    def get_active_instances(self) -> List[InstanceRecord]:
        """Return list of instances currently accepting traffic."""
        return [
            inst for inst in self._instances.values()
            if inst.is_accepting_traffic and inst.status in [InstanceStatus.HEALTHY, InstanceStatus.DEGRADED]
        ]

    def get_active_healthy_instance(self) -> Optional[InstanceRecord]:
        """Return a healthy instance from the active routing pool using round-robin distribution.
        
        Fail-Safe: Always picks from healthy instances that are accepting traffic.
        """
        active = self.get_active_instances()
        if not active:
            # Fallback to any registered instance if all are marked down (fail-open)
            all_inst = list(self._instances.values())
            if all_inst:
                logger.warning("No healthy active instances found in pool. Falling back to primary instance.")
                return all_inst[0]
            return None

        # Round-robin selection
        selected = active[self._round_robin_index % len(active)]
        self._round_robin_index = (self._round_robin_index + 1) % len(active)
        return selected

    def isolate_instance(self, instance_id: str) -> bool:
        """Mark an instance as ISOLATED and remove it from active traffic routing."""
        inst = self._instances.get(instance_id)
        if not inst:
            return False

        inst.status = InstanceStatus.ISOLATED
        inst.is_accepting_traffic = False
        inst.consecutive_successes = 0

        # Update cluster isolation state
        isolated_count = sum(1 for i in self._instances.values() if i.status == InstanceStatus.ISOLATED)
        if isolated_count > 0:
            self._isolation_state = IsolationState.REROUTED

        logger.warning(f"Instance ISOLATED: {instance_id}. Removed from ingress traffic pool.")
        return True

    def reintroduce_instance(self, instance_id: str) -> bool:
        """Reintroduce a healthy/recovered instance back into active traffic pool."""
        inst = self._instances.get(instance_id)
        if not inst:
            return False

        inst.status = InstanceStatus.HEALTHY
        inst.is_accepting_traffic = True
        inst.consecutive_failures = 0
        inst.consecutive_successes = 3

        # Update cluster isolation state if all are healthy
        isolated_count = sum(1 for i in self._instances.values() if i.status == InstanceStatus.ISOLATED)
        if isolated_count == 0:
            self._isolation_state = IsolationState.NORMAL

        logger.info(f"Instance REINTRODUCED: {instance_id}. Added back to ingress traffic pool.")
        return True

    def set_instance_status(
        self,
        instance_id: str,
        status: InstanceStatus,
        is_accepting_traffic: Optional[bool] = None,
    ) -> bool:
        """Update the operational status of an instance."""
        inst = self._instances.get(instance_id)
        if not inst:
            return False
        inst.status = status
        if is_accepting_traffic is not None:
            inst.is_accepting_traffic = is_accepting_traffic
        return True

    def update_health_probe_result(
        self,
        instance_id: str,
        is_healthy: bool,
        status_code: int,
        latency_ms: float,
    ) -> Optional[InstanceRecord]:
        """Record the outcome of a health check probe for an instance."""
        inst = self._instances.get(instance_id)
        if not inst:
            return None

        inst.last_health_check_timestamp = time.time()
        inst.last_status_code = status_code
        inst.average_latency_ms = round((inst.average_latency_ms * 0.7) + (latency_ms * 0.3), 2) if inst.average_latency_ms > 0 else round(latency_ms, 2)

        if is_healthy:
            inst.consecutive_successes += 1
            inst.consecutive_failures = 0
            if inst.status == InstanceStatus.DEGRADED:
                inst.status = InstanceStatus.HEALTHY
        else:
            inst.consecutive_failures += 1
            inst.consecutive_successes = 0
            inst.error_count += 1
            if inst.status == InstanceStatus.HEALTHY:
                inst.status = InstanceStatus.DEGRADED
            elif inst.consecutive_failures >= 2 and inst.status != InstanceStatus.ISOLATED:
                inst.status = InstanceStatus.UNHEALTHY

        return inst

    @property
    def isolation_state(self) -> IsolationState:
        return self._isolation_state

    @isolation_state.setter
    def isolation_state(self, state: IsolationState) -> None:
        self._isolation_state = state

    def get_cluster_snapshot(self, recovery_confidence: float = 100.0) -> ClusterHealthSnapshot:
        """Return an aggregate snapshot of cluster instances and health."""
        all_inst = list(self._instances.values())
        active_inst = [i for i in all_inst if i.is_accepting_traffic]
        healthy_inst = [i for i in all_inst if i.status == InstanceStatus.HEALTHY]
        isolated_inst = [i for i in all_inst if i.status == InstanceStatus.ISOLATED]

        if isolated_inst:
            cluster_status = "DEGRADED" if active_inst else "UNHEALTHY"
        elif any(i.status == InstanceStatus.DEGRADED for i in all_inst):
            cluster_status = "DEGRADED"
        elif any(i.status in [InstanceStatus.RECOVERING, InstanceStatus.STARTING] for i in all_inst):
            cluster_status = "RECOVERING"
        else:
            cluster_status = "HEALTHY"

        return ClusterHealthSnapshot(
            cluster_status=cluster_status,
            isolation_state=self._isolation_state,
            total_instances_count=len(all_inst),
            active_instances_count=len(active_inst),
            healthy_instances_count=len(healthy_inst),
            isolated_instances_count=len(isolated_inst),
            instances=all_inst,
            recovery_confidence=round(recovery_confidence, 2),
            last_updated=time.time(),
        )

    def reset_all_instances(self) -> None:
        """Reset all instances to healthy operational state."""
        for inst in self._instances.values():
            inst.status = InstanceStatus.HEALTHY
            inst.is_accepting_traffic = True
            inst.consecutive_failures = 0
            inst.consecutive_successes = 3
            inst.last_status_code = 200
        self._isolation_state = IsolationState.NORMAL
        logger.info("Reset all instances to HEALTHY.")


# Global singleton service registry instance
service_registry = ServiceRegistry()
