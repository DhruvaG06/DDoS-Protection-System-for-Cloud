"""Autonomous Self-Healing Recovery Controller (Phase 4).

Implements OneChance's Core USP:
DETECT → ISOLATE → REROUTE → REPLACE → HEALTH CHECK → REINTRODUCE → VERIFY RECOVERY

Orchestrates container isolation, traffic rerouting, container replacement/restart,
health verification, and calculates the operational Recovery Confidence Score (0–100).
"""

import asyncio
from collections import deque
import logging
import time
import uuid
from typing import Deque, Dict, List, Optional
import httpx

from onechance.models.health import (
    InstanceRecord,
    InstanceStatus,
    IsolationState,
    RecoveryEvent,
    RecoveryEventType,
    RecoveryVerificationMetrics,
)
from onechance.recovery.service_registry import ServiceRegistry, service_registry

logger = logging.getLogger("onechance.recovery_controller")


class RecoveryController:
    """Autonomous Self-Healing Controller orchestrating closed-loop container recovery."""

    def __init__(
        self,
        registry: Optional[ServiceRegistry] = None,
        health_verification_probes: int = 3,
        probe_interval_seconds: float = 0.5,
        baseline_latency_ms: float = 10.0,
    ):
        self.registry = registry or service_registry
        self.health_verification_probes = health_verification_probes
        self.probe_interval_seconds = probe_interval_seconds
        self.baseline_latency_ms = baseline_latency_ms

        # In-memory buffer of recent recovery events
        self._event_timeline: Deque[RecoveryEvent] = deque(maxlen=200)
        self._is_recovering: Dict[str, bool] = {}
        self._last_verification_metrics: Optional[RecoveryVerificationMetrics] = None

    def record_event(
        self,
        event_type: Optional[RecoveryEventType] = None,
        instance_id: Optional[str] = None,
        trigger_reason: str = "Autonomous recovery action",
        status: str = "SUCCESS",
        recovery_confidence: Optional[float] = None,
        metadata: Optional[Dict] = None,
        # Legacy parameters for backwards compatibility
        action: Optional[str] = None,
        target_instance: Optional[str] = None,
        details: Optional[Dict] = None,
    ) -> RecoveryEvent:
        """Create, buffer, log, and return a structured recovery event."""
        # Resolve legacy aliases
        if event_type is None and action is not None:
            try:
                event_type = RecoveryEventType[action]
            except Exception:
                event_type = RecoveryEventType.INSTANCE_ISOLATED

        final_event_type = event_type or RecoveryEventType.INSTANCE_ISOLATED
        final_instance_id = instance_id or target_instance or "app-1"
        final_metadata = metadata or details or {}

        event = RecoveryEvent(
            event_id=f"rec_{uuid.uuid4().hex[:12]}",
            timestamp=time.time(),
            event_type=final_event_type,
            instance_id=final_instance_id,
            status=status,
            trigger_reason=trigger_reason,
            recovery_confidence=recovery_confidence,
            metadata=final_metadata,
        )
        self._event_timeline.append(event)
        logger.info(f"Recovery Event: [{final_event_type.value}] on {final_instance_id} ({status}) - {trigger_reason}")
        return event

    def get_timeline(self, limit: int = 50) -> List[RecoveryEvent]:
        """Return chronological list of recovery events."""
        events = list(self._event_timeline)
        return events[-limit:]

    async def execute_autonomous_recovery(self, instance_id: str, trigger_reason: str = "Health check failure detected") -> bool:
        """Executes the complete autonomous self-healing pipeline for an unhealthy instance."""
        if self._is_recovering.get(instance_id, False):
            logger.warning(f"Recovery already actively executing for instance {instance_id}.")
            return False

        inst = self.registry.get_instance(instance_id)
        if not inst:
            logger.error(f"Cannot recover unregistered instance: {instance_id}")
            return False

        self._is_recovering[instance_id] = True
        logger.info(f"=== INITIATING AUTONOMOUS RECOVERY PIPELINE FOR {instance_id} ===")

        try:
            # -------------------------------------------------------------
            # STEP 1: DETECT / RECORD UNHEALTHY
            # -------------------------------------------------------------
            self.registry.set_instance_status(instance_id, InstanceStatus.UNHEALTHY)
            self.record_event(
                event_type=RecoveryEventType.INSTANCE_UNHEALTHY,
                instance_id=instance_id,
                trigger_reason=trigger_reason,
                metadata={"url": inst.url, "error_count": inst.error_count},
            )

            # -------------------------------------------------------------
            # STEP 2: ISOLATE (Remove from active traffic)
            # -------------------------------------------------------------
            self.registry.isolate_instance(instance_id)
            self.record_event(
                event_type=RecoveryEventType.INSTANCE_ISOLATED,
                instance_id=instance_id,
                trigger_reason=f"Detached {instance_id} from ingress gateway traffic pool",
                metadata={"url": inst.url, "status": InstanceStatus.ISOLATED.value},
            )

            # -------------------------------------------------------------
            # STEP 3: REROUTE (Ensure healthy nodes continue serving)
            # -------------------------------------------------------------
            active_instances = self.registry.get_active_instances()
            active_ids = [i.instance_id for i in active_instances]
            self.record_event(
                event_type=RecoveryEventType.TRAFFIC_REROUTED,
                instance_id=instance_id,
                trigger_reason=f"Gateway traffic rerouted across {len(active_instances)} healthy instances: {active_ids}",
                metadata={"active_instances": active_ids, "active_count": len(active_instances)},
            )

            # -------------------------------------------------------------
            # STEP 4: REPLACE (Start clean replacement / reset container)
            # -------------------------------------------------------------
            self.registry.set_instance_status(instance_id, InstanceStatus.RECOVERING, is_accepting_traffic=False)
            self.record_event(
                event_type=RecoveryEventType.REPLACEMENT_STARTED,
                instance_id=instance_id,
                status="IN_PROGRESS",
                trigger_reason=f"Spawned replacement sequence for container {instance_id}",
                metadata={"target_url": inst.url},
            )

            # Reset container state / restore healthy process
            await self._restore_container_process(inst)

            # -------------------------------------------------------------
            # STEP 5: HEALTH CHECK & VERIFICATION (Require N consecutive checks)
            # -------------------------------------------------------------
            logger.info(f"Executing {self.health_verification_probes} health checks for {instance_id}...")
            verified_healthy = await self._run_health_verification_probes(inst)

            if not verified_healthy:
                logger.error(f"Health verification failed for {instance_id}. Keeping isolated.")
                self.registry.set_instance_status(instance_id, InstanceStatus.ISOLATED, is_accepting_traffic=False)
                return False

            self.record_event(
                event_type=RecoveryEventType.REPLACEMENT_HEALTHY,
                instance_id=instance_id,
                trigger_reason=f"Replacement passed {self.health_verification_probes} consecutive health probes",
                metadata={"consecutive_successes": inst.consecutive_successes, "latency_ms": inst.average_latency_ms},
            )

            # -------------------------------------------------------------
            # STEP 6: REINTRODUCE (Add back to active routing pool)
            # -------------------------------------------------------------
            self.registry.reintroduce_instance(instance_id)
            self.record_event(
                event_type=RecoveryEventType.INSTANCE_REINTRODUCED,
                instance_id=instance_id,
                trigger_reason=f"Reintroduced {instance_id} into active gateway traffic distribution pool",
                metadata={"url": inst.url, "active_pool_size": len(self.registry.get_active_instances())},
            )

            # -------------------------------------------------------------
            # STEP 7: SERVICE RECOVERY VERIFIED (Calculate Recovery Confidence)
            # -------------------------------------------------------------
            verification = self.calculate_recovery_confidence()
            self._last_verification_metrics = verification
            self.record_event(
                event_type=RecoveryEventType.SERVICE_RECOVERY_VERIFIED,
                instance_id=instance_id,
                trigger_reason=f"Full cluster recovery verified with confidence score {verification.recovery_confidence:.1f}/100",
                recovery_confidence=verification.recovery_confidence,
                metadata=verification.model_dump(),
            )

            logger.info(f"=== AUTONOMOUS RECOVERY COMPLETED SUCCESSFULLY FOR {instance_id} (Confidence: {verification.recovery_confidence:.1f}%) ===")
            return True

        finally:
            self._is_recovering[instance_id] = False

    async def _restore_container_process(self, instance: InstanceRecord) -> bool:
        """Call the container's reset endpoint or restart simulation."""
        reset_url = f"{instance.url.rstrip('/')}/api/reset-health"
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.post(reset_url)
                return resp.status_code == 200
        except Exception as e:
            logger.warning(f"Could not reach reset endpoint for {instance.instance_id}: {e}")
            return False

    async def _run_health_verification_probes(self, instance: InstanceRecord) -> bool:
        """Perform N consecutive health probes against the instance."""
        health_url = f"{instance.url.rstrip('/')}/api/health"
        consecutive_passes = 0

        for probe_num in range(self.health_verification_probes):
            await asyncio.sleep(self.probe_interval_seconds)
            try:
                async with httpx.AsyncClient(timeout=2.0) as client:
                    resp = await client.get(health_url)
                    if resp.status_code == 200:
                        consecutive_passes += 1
                        logger.debug(f"Health verification probe {probe_num+1}/{self.health_verification_probes} passed for {instance.instance_id}")
                    else:
                        logger.warning(f"Health verification probe {probe_num+1} failed with HTTP {resp.status_code}")
            except Exception as e:
                logger.warning(f"Health verification probe {probe_num+1} failed with exception: {e}")

        return consecutive_passes >= self.health_verification_probes

    def calculate_recovery_confidence(self) -> RecoveryVerificationMetrics:
        """Calculates the composite Recovery Confidence Score (0–100) based on operational metrics.
        
        Operational Indicators:
        - Healthy Instance Ratio (Weight: 40%): Active healthy nodes vs total expected nodes
        - Health Probe Success Rate (Weight: 30%): Success rate on recent checks
        - Latency Stability Score (Weight: 20%): Proximity to baseline latency
        - Error Rate Score (Weight: 10%): Inverted recent error rate
        """
        all_instances = self.registry.get_all_instances()
        if not all_instances:
            return RecoveryVerificationMetrics(
                recovery_confidence=0.0,
                healthy_instances_ratio=0.0,
                health_probe_success_rate=0.0,
                latency_stability_score=0.0,
                error_rate_score=0.0,
            )

        # 1. Healthy Instances Ratio (0 - 40 pts)
        healthy_count = sum(1 for i in all_instances if i.status == InstanceStatus.HEALTHY and i.is_accepting_traffic)
        total_count = len(all_instances)
        healthy_ratio = healthy_count / total_count
        ratio_score = healthy_ratio * 40.0

        # 2. Health Probe Success Rate (0 - 30 pts)
        probe_success_count = sum(1 for i in all_instances if i.consecutive_successes >= 1 and i.last_status_code == 200)
        probe_success_rate = probe_success_count / total_count
        probe_score = probe_success_rate * 30.0

        # 3. Latency Stability Score (0 - 20 pts)
        avg_latencies = [i.average_latency_ms for i in all_instances if i.average_latency_ms > 0]
        cluster_avg_latency = sum(avg_latencies) / len(avg_latencies) if avg_latencies else self.baseline_latency_ms
        latency_factor = min(1.0, self.baseline_latency_ms / max(cluster_avg_latency, 1.0))
        latency_score = latency_factor * 20.0

        # 4. Error Rate Score (0 - 10 pts)
        total_errors = sum(i.error_count for i in all_instances)
        error_penalty = min(1.0, total_errors / max(total_count * 10, 1))
        error_score = (1.0 - error_penalty) * 10.0

        composite_confidence = min(100.0, max(0.0, ratio_score + probe_score + latency_score + error_score))

        return RecoveryVerificationMetrics(
            recovery_confidence=round(composite_confidence, 2),
            healthy_instances_ratio=round(healthy_ratio, 3),
            health_probe_success_rate=round(probe_success_rate, 3),
            latency_stability_score=round(latency_factor, 3),
            error_rate_score=round(1.0 - error_penalty, 3),
        )

    async def simulate_failure(self, instance_id: str, reason: str = "Deterministic test failure") -> Dict:
        """Trigger deterministic failure on a selected instance and launch autonomous self-healing."""
        inst = self.registry.get_instance(instance_id)
        if not inst:
            return {"status": "error", "message": f"Instance '{instance_id}' not found in registry"}

        logger.warning(f"=== SIMULATING DETERMINISTIC FAILURE ON {instance_id}: {reason} ===")

        # Trigger failure on the target container
        fail_url = f"{inst.url.rstrip('/')}/api/simulate-failure"
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                await client.post(fail_url, params={"reason": reason})
        except Exception as e:
            logger.warning(f"Failure simulation HTTP call to {instance_id} failed: {e}")

        # Mark as DEGRADED / UNHEALTHY in registry
        self.registry.set_instance_status(instance_id, InstanceStatus.UNHEALTHY)

        # Launch autonomous self-healing task in background
        recovery_task = asyncio.create_task(
            self.execute_autonomous_recovery(instance_id=instance_id, trigger_reason=reason)
        )

        return {
            "status": "failure_simulated",
            "instance_id": instance_id,
            "reason": reason,
            "recovery_task_started": True,
            "message": f"Failure simulated on {instance_id}. Autonomous recovery initiated.",
        }

    def reset_recovery_state(self) -> None:
        """Reset all instance states and recovery timeline for a fresh demonstration."""
        self.registry.reset_all_instances()
        self._event_timeline.clear()
        self._is_recovering.clear()
        self._last_verification_metrics = None
        logger.info("Reset recovery controller state.")


# Global recovery controller instance
recovery_controller = RecoveryController()
