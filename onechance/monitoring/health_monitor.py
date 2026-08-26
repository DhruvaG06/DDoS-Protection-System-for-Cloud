"""Backend Service Health Monitoring Module & Interface.

Continuously probes protected target workload instances to detect:
- Service degradation / latency spikes
- Unresponsive or crashed containers (HTTP 5xx / connection timeouts)
- Triggers notification to the Recovery Controller upon crossing failure thresholds.
"""

import asyncio
import logging
import time
from typing import Callable, Optional
import httpx
from onechance.models.health import InstanceStatus, IsolationState, ServiceHealth

logger = logging.getLogger("onechance.health_monitor")


class HealthMonitor:
    """Monitors origin workload instances and detects service failure."""

    def __init__(
        self,
        target_url: str,
        interval_seconds: float = 3.0,
        failure_threshold: int = 3,
        timeout_seconds: float = 2.0,
        on_unhealthy_callback: Optional[Callable[[ServiceHealth], None]] = None,
    ):
        self.primary_url = target_url
        self.active_target_url = target_url
        self.interval_seconds = interval_seconds
        self.failure_threshold = failure_threshold
        self.timeout_seconds = timeout_seconds
        self.on_unhealthy_callback = on_unhealthy_callback

        self.service_health = ServiceHealth(
            primary_instance_id="target-instance-primary",
            primary_status=InstanceStatus.HEALTHY,
            primary_url=target_url,
            active_target_url=target_url,
            consecutive_failures=0,
            average_latency_ms=0.0,
            last_health_check_timestamp=time.time(),
            isolation_state=IsolationState.NORMAL,
        )

        self._running = False
        self._monitor_task: Optional[asyncio.Task] = None

    async def check_target_health(self) -> bool:
        """Perform a single HTTP health probe against the monitored instance."""
        start = time.time()
        url = f"{self.service_health.active_target_url.rstrip('/')}/health"
        is_healthy = False
        latency_ms = 0.0

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                resp = await client.get(url)
                latency_ms = (time.time() - start) * 1000.0
                if resp.status_code == 200:
                    is_healthy = True
        except Exception as e:
            latency_ms = (time.time() - start) * 1000.0
            logger.warning(f"Health probe to {url} failed: {e}")
            is_healthy = False

        self.service_health.last_health_check_timestamp = time.time()
        self.service_health.average_latency_ms = round(latency_ms, 2)

        if is_healthy:
            self.service_health.consecutive_failures = 0
            if self.service_health.primary_status != InstanceStatus.ISOLATED:
                self.service_health.primary_status = InstanceStatus.HEALTHY
        else:
            self.service_health.consecutive_failures += 1
            if self.service_health.consecutive_failures >= self.failure_threshold:
                self.service_health.primary_status = InstanceStatus.UNHEALTHY
                if self.on_unhealthy_callback:
                    self.on_unhealthy_callback(self.service_health)
            else:
                self.service_health.primary_status = InstanceStatus.DEGRADED

        return is_healthy

    async def _run_loop(self) -> None:
        """Background health polling loop."""
        while self._running:
            try:
                await self.check_target_health()
            except Exception as e:
                logger.error(f"Error during health check loop: {e}")
            await asyncio.sleep(self.interval_seconds)

    def start(self) -> None:
        """Start the background health monitor task."""
        if not self._running:
            self._running = True
            self._monitor_task = asyncio.create_task(self._run_loop())
            logger.info("Health monitoring started.")

    def stop(self) -> None:
        """Stop the background health monitor task."""
        self._running = False
        if self._monitor_task:
            self._monitor_task.cancel()
            logger.info("Health monitoring stopped.")

    def get_current_health(self) -> ServiceHealth:
        """Retrieve current health snapshot."""
        return self.service_health
