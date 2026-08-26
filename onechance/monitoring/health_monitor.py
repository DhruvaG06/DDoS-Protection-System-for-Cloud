"""Backend Service Health Monitoring Module (Phase 4).

Periodically probes all application container instances registered in the ServiceRegistry:
- Tracks latency, availability, and consecutive failure/success rates
- Identifies degraded or failed instances
- Emits INSTANCE_UNHEALTHY events and triggers Autonomous Recovery Controller
"""

import asyncio
import logging
import time
from typing import Callable, Dict, List, Optional
import httpx

from onechance.models.health import (
    ClusterHealthSnapshot,
    InstanceRecord,
    InstanceStatus,
    RecoveryEventType,
)
from onechance.recovery.service_registry import ServiceRegistry, service_registry

logger = logging.getLogger("onechance.health_monitor")


class HealthMonitor:
    """Multi-instance health monitor continuously tracking backend containers."""

    def __init__(
        self,
        registry: Optional[ServiceRegistry] = None,
        interval_seconds: float = 2.0,
        failure_threshold: int = 3,
        success_threshold: int = 3,
        timeout_seconds: float = 2.0,
        on_unhealthy_callback: Optional[Callable[[str, str], None]] = None,
    ):
        self.registry = registry or service_registry
        self.interval_seconds = interval_seconds
        self.failure_threshold = failure_threshold
        self.success_threshold = success_threshold
        self.timeout_seconds = timeout_seconds
        self.on_unhealthy_callback = on_unhealthy_callback

        self._running = False
        self._monitor_task: Optional[asyncio.Task] = None
        self._last_probe_stats: Dict[str, Dict] = {}

    async def probe_instance(self, instance: InstanceRecord) -> bool:
        """Perform an HTTP health check probe against a single registered instance."""
        start_time = time.time()
        health_url = f"{instance.url.rstrip('/')}/api/health"
        is_healthy = False
        status_code = 0
        latency_ms = 0.0

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                resp = await client.get(health_url)
                latency_ms = (time.time() - start_time) * 1000.0
                status_code = resp.status_code
                if resp.status_code == 200:
                    is_healthy = True
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000.0
            status_code = 503
            is_healthy = False

        # Update registry state
        previous_status = instance.status
        updated_inst = self.registry.update_health_probe_result(
            instance_id=instance.instance_id,
            is_healthy=is_healthy,
            status_code=status_code,
            latency_ms=latency_ms,
        )

        self._last_probe_stats[instance.instance_id] = {
            "timestamp": time.time(),
            "status_code": status_code,
            "latency_ms": round(latency_ms, 2),
            "is_healthy": is_healthy,
        }

        # Check for failure trigger
        if not is_healthy and updated_inst:
            if updated_inst.consecutive_failures >= self.failure_threshold:
                if previous_status not in [InstanceStatus.UNHEALTHY, InstanceStatus.ISOLATED, InstanceStatus.RECOVERING]:
                    logger.warning(
                        f"Instance {instance.instance_id} crossed failure threshold ({updated_inst.consecutive_failures} failures). Triggering recovery."
                    )
                    if self.on_unhealthy_callback:
                        reason = f"Health check failed {updated_inst.consecutive_failures} consecutive times (HTTP {status_code})"
                        # Execute callback asynchronously if possible or direct
                        try:
                            res = self.on_unhealthy_callback(instance.instance_id, reason)
                            if asyncio.iscoroutine(res):
                                asyncio.create_task(res)
                        except Exception as cb_err:
                            logger.error(f"Error in on_unhealthy_callback: {cb_err}")

        return is_healthy

    async def probe_all_instances(self) -> List[bool]:
        """Probe all registered instances in parallel."""
        instances = self.registry.get_all_instances()
        if not instances:
            return []
        tasks = [self.probe_instance(inst) for inst in instances]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, bool)]

    async def _run_loop(self) -> None:
        """Background continuous monitoring loop."""
        while self._running:
            try:
                await self.probe_all_instances()
            except Exception as e:
                logger.error(f"Error during health check loop: {e}")
            await asyncio.sleep(self.interval_seconds)

    def start(self) -> None:
        """Start background polling task."""
        if not self._running:
            self._running = True
            self._monitor_task = asyncio.create_task(self._run_loop())
            logger.info("Health monitoring background loop started.")

    def stop(self) -> None:
        """Stop background polling task."""
        self._running = False
        if self._monitor_task:
            self._monitor_task.cancel()
            self._monitor_task = None
            logger.info("Health monitoring background loop stopped.")

    def get_instance_probe_stats(self, instance_id: str) -> Optional[Dict]:
        """Return the most recent probe statistics for an instance."""
        return self._last_probe_stats.get(instance_id)

    def get_cluster_snapshot(self, recovery_confidence: float = 100.0) -> ClusterHealthSnapshot:
        """Return current snapshot of cluster health."""
        return self.registry.get_cluster_snapshot(recovery_confidence=recovery_confidence)


# Global health monitor instance
health_monitor = HealthMonitor()
