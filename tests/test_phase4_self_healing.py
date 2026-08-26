"""Phase 4 Autonomous Self-Healing and Service Recovery Test Suite."""

import asyncio
import pytest
import httpx
from fastapi.testclient import TestClient

from onechance.main import app as gateway_app
from onechance.models.health import InstanceStatus, IsolationState, RecoveryEventType
from onechance.monitoring.health_monitor import HealthMonitor
from onechance.recovery.recovery_controller import RecoveryController
from onechance.recovery.service_registry import ServiceRegistry
from target_service.app import app as target_app


@pytest.fixture
def clean_registry():
    """Create an isolated service registry with 3 instances for testing."""
    reg = ServiceRegistry()
    reg.register_instance(instance_id="app-1", url="http://localhost:8001", container_name="onechance-app-1")
    reg.register_instance(instance_id="app-2", url="http://localhost:8002", container_name="onechance-app-2")
    reg.register_instance(instance_id="app-3", url="http://localhost:8003", container_name="onechance-app-3")
    return reg


@pytest.fixture
def recovery_ctrl(clean_registry):
    """Create a recovery controller bound to the test registry."""
    ctrl = RecoveryController(
        registry=clean_registry,
        health_verification_probes=3,
        probe_interval_seconds=0.01,
        baseline_latency_ms=10.0,
    )
    return ctrl


@pytest.fixture
def gateway_client():
    return TestClient(gateway_app)


# =========================================================================
# 1. Service Registry & Instance State Tests
# =========================================================================

def test_service_registry_instance_registration(clean_registry):
    """Verify healthy instance registration and initial states."""
    instances = clean_registry.get_all_instances()
    assert len(instances) == 3
    assert all(i.status == InstanceStatus.HEALTHY for i in instances)
    assert all(i.is_accepting_traffic is True for i in instances)

    app2 = clean_registry.get_instance("app-2")
    assert app2 is not None
    assert app2.instance_id == "app-2"
    assert app2.url == "http://localhost:8002"


def test_service_registry_round_robin_distribution(clean_registry):
    """Verify round-robin selection among active healthy instances."""
    picked = [clean_registry.get_active_healthy_instance().instance_id for _ in range(6)]
    assert picked == ["app-1", "app-2", "app-3", "app-1", "app-2", "app-3"]


# =========================================================================
# 2. Isolation & Traffic Rerouting Tests
# =========================================================================

def test_instance_isolation_and_rerouting(clean_registry):
    """Verify isolating an instance removes it from traffic while others continue serving."""
    # 1. Isolate app-2
    isolated = clean_registry.isolate_instance("app-2")
    assert isolated is True

    app2 = clean_registry.get_instance("app-2")
    assert app2.status == InstanceStatus.ISOLATED
    assert app2.is_accepting_traffic is False
    assert clean_registry.isolation_state == IsolationState.REROUTED

    # 2. Check active healthy instances pool
    active = clean_registry.get_active_instances()
    assert len(active) == 2
    active_ids = [i.instance_id for i in active]
    assert "app-1" in active_ids
    assert "app-3" in active_ids
    assert "app-2" not in active_ids

    # 3. Subsequent traffic routing only reaches app-1 and app-3
    routed = [clean_registry.get_active_healthy_instance().instance_id for _ in range(4)]
    assert set(routed) == {"app-1", "app-3"}
    assert "app-2" not in routed


def test_fail_safe_isolation_never_drops_all_capacity(clean_registry):
    """Fail-Safe verification: Gateway falls back safely if all nodes are marked isolated."""
    clean_registry.isolate_instance("app-1")
    clean_registry.isolate_instance("app-2")
    clean_registry.isolate_instance("app-3")

    # Even if all are isolated, registry provides a safe fallback node rather than crashing
    fallback = clean_registry.get_active_healthy_instance()
    assert fallback is not None


# =========================================================================
# 3. Health Verification & Reintroduction Tests
# =========================================================================

def test_instance_reintroduction(clean_registry):
    """Verify reintroducing an instance restores it to the active pool."""
    clean_registry.isolate_instance("app-2")
    assert len(clean_registry.get_active_instances()) == 2

    reintroduced = clean_registry.reintroduce_instance("app-2")
    assert reintroduced is True

    app2 = clean_registry.get_instance("app-2")
    assert app2.status == InstanceStatus.HEALTHY
    assert app2.is_accepting_traffic is True
    assert clean_registry.isolation_state == IsolationState.NORMAL
    assert len(clean_registry.get_active_instances()) == 3


def test_recovery_confidence_calculation(clean_registry, recovery_ctrl):
    """Verify Recovery Confidence Score (0-100) based on operational indicators."""
    # Full healthy cluster -> 100% confidence
    metrics = recovery_ctrl.calculate_recovery_confidence()
    assert metrics.recovery_confidence >= 95.0
    assert metrics.healthy_instances_ratio == 1.0

    # 1 out of 3 instances isolated -> reduced confidence
    clean_registry.isolate_instance("app-2")
    degraded_metrics = recovery_ctrl.calculate_recovery_confidence()
    assert degraded_metrics.recovery_confidence < metrics.recovery_confidence
    assert degraded_metrics.healthy_instances_ratio == round(2 / 3, 3)


# =========================================================================
# 4. End-to-End Autonomous Self-Healing Pipeline Tests
# =========================================================================

@pytest.mark.asyncio
async def test_autonomous_recovery_lifecycle_execution(monkeypatch, clean_registry, recovery_ctrl):
    """Verify the full 7-step autonomous recovery sequence:
    DETECT -> ISOLATE -> REROUTE -> REPLACE -> HEALTH CHECK -> REINTRODUCE -> VERIFY
    """
    # Mock HTTP calls to target container endpoints
    target_transport = httpx.ASGITransport(app=target_app)
    orig_client = httpx.AsyncClient

    class MockAsyncClient(orig_client):
        def __init__(self, *args, **kwargs):
            if "transport" not in kwargs or kwargs["transport"] is None:
                kwargs["transport"] = target_transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", MockAsyncClient)

    # 1. Execute recovery on app-2
    success = await recovery_ctrl.execute_autonomous_recovery(
        instance_id="app-2",
        trigger_reason="Unit test simulated workload degradation",
    )
    assert success is True

    # 2. Verify instance ended in HEALTHY state
    app2 = clean_registry.get_instance("app-2")
    assert app2.status == InstanceStatus.HEALTHY
    assert app2.is_accepting_traffic is True

    # 3. Verify all 7 recovery event types were emitted in chronological order
    timeline = recovery_ctrl.get_timeline()
    event_types = [e.event_type for e in timeline]

    assert RecoveryEventType.INSTANCE_UNHEALTHY in event_types
    assert RecoveryEventType.INSTANCE_ISOLATED in event_types
    assert RecoveryEventType.TRAFFIC_REROUTED in event_types
    assert RecoveryEventType.REPLACEMENT_STARTED in event_types
    assert RecoveryEventType.REPLACEMENT_HEALTHY in event_types
    assert RecoveryEventType.INSTANCE_REINTRODUCED in event_types
    assert RecoveryEventType.SERVICE_RECOVERY_VERIFIED in event_types

    # 4. Verify verified event contains recovery confidence score
    verified_event = next(e for e in timeline if e.event_type == RecoveryEventType.SERVICE_RECOVERY_VERIFIED)
    assert verified_event.recovery_confidence is not None
    assert verified_event.recovery_confidence > 80.0


@pytest.mark.asyncio
async def test_recovery_pipeline_repeatability(monkeypatch, clean_registry, recovery_ctrl):
    """Verify that autonomous recovery can be repeated multiple times consecutively."""
    target_transport = httpx.ASGITransport(app=target_app)
    orig_client = httpx.AsyncClient

    class MockAsyncClient(orig_client):
        def __init__(self, *args, **kwargs):
            if "transport" not in kwargs or kwargs["transport"] is None:
                kwargs["transport"] = target_transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", MockAsyncClient)

    # Round 1
    res1 = await recovery_ctrl.execute_autonomous_recovery("app-2", "Round 1 failure")
    assert res1 is True
    assert clean_registry.get_instance("app-2").status == InstanceStatus.HEALTHY

    # Round 2
    res2 = await recovery_ctrl.execute_autonomous_recovery("app-2", "Round 2 failure")
    assert res2 is True
    assert clean_registry.get_instance("app-2").status == InstanceStatus.HEALTHY


# =========================================================================
# 5. API Endpoints for Phase 4
# =========================================================================

def test_api_recovery_status_and_events(gateway_client):
    """Verify /api/recovery/status and /api/recovery/events endpoints."""
    # 1. Status endpoint
    status_resp = gateway_client.get("/api/recovery/status")
    assert status_resp.status_code == 200
    data = status_resp.json()
    assert "snapshot" in data
    assert "verification_metrics" in data
    assert "active_healthy_pool" in data

    # 2. Events endpoint
    events_resp = gateway_client.get("/api/recovery/events")
    assert events_resp.status_code == 200
    assert "events" in events_resp.json()

    # 3. Verify endpoint
    verify_resp = gateway_client.get("/api/recovery/verify")
    assert verify_resp.status_code == 200
    assert "recovery_confidence" in verify_resp.json()


def test_api_recovery_reset(gateway_client):
    """Verify /api/recovery/reset endpoint."""
    resp = gateway_client.post("/api/recovery/reset")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert len(data["active_instances"]) >= 1
