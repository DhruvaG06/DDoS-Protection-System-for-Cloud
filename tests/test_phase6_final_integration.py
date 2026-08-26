"""OneChance — Phase 6: Final MVP Integration, Reliability & Fail-Safe Tests."""

import asyncio
import time
import pytest
import httpx
from fastapi.testclient import TestClient

from onechance.core.detector import ModularDetectorEngine, RandomForestDetector
from onechance.core.feature_extractor import FeatureExtractor
from onechance.core.mitigator import Mitigator
from onechance.core.policy_engine import PolicyEngine
from onechance.core.risk_scorer import RiskScorer
from onechance.main import app as gateway_app
from onechance.models.decisions import ActionEnum, ThreatLevel
from onechance.models.health import InstanceStatus, IsolationState, RecoveryEventType
from onechance.models.traffic import AttackSourceType, IncomingRequest
from onechance.recovery.recovery_controller import RecoveryController
from onechance.recovery.service_registry import ServiceRegistry
from scripts.evaluate_mvp import evaluate_detector_quality
from target_service.app import app as target_app


@pytest.fixture
def test_registry():
    reg = ServiceRegistry(init_defaults=False)
    reg.register_instance("app-1", "http://localhost:8001")
    reg.register_instance("app-2", "http://localhost:8002")
    reg.register_instance("app-3", "http://localhost:8003")
    return reg


@pytest.fixture
def test_controller(test_registry):
    return RecoveryController(
        registry=test_registry,
        health_verification_probes=3,
        probe_interval_seconds=0.01,
        baseline_latency_ms=10.0,
    )


@pytest.fixture
def gateway_client():
    return TestClient(gateway_app)


# =========================================================================
# 1. Full Closed-Loop Deterministic Scenario Test
# =========================================================================

@pytest.mark.asyncio
async def test_full_closed_loop_story(monkeypatch, test_registry, test_controller):
    """Test the complete OneChance MVP story:
    NORMAL -> ATTACK -> DETECT -> RISK SCORE -> MITIGATE -> ISOLATE -> REROUTE -> REPLACE -> VERIFY -> RESET
    """
    # Mock container HTTP resets & health checks
    target_transport = httpx.ASGITransport(app=target_app)
    orig_client = httpx.AsyncClient

    class MockAsyncClient(orig_client):
        def __init__(self, *args, **kwargs):
            if "transport" not in kwargs or kwargs["transport"] is None:
                kwargs["transport"] = target_transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", MockAsyncClient)

    # 1. Normal State
    instances = test_registry.get_all_instances()
    assert len(instances) == 3
    assert all(i.status == InstanceStatus.HEALTHY for i in instances)

    # 2. Simulate Attack & Detection
    extractor = FeatureExtractor(window_duration_seconds=5.0)
    detector = ModularDetectorEngine()
    scorer = RiskScorer()
    engine = PolicyEngine()

    for i in range(15):
        req = IncomingRequest(
            client_ip="203.0.113.50",
            method="GET",
            path="/api/expensive-operation",
            timestamp=time.time() + (i * 0.01),
            user_agent="External-Botnet/4.0",
        )
        features = extractor.extract_features(req)
        anomaly_prob = detector.predict_anomaly_probability(features)
        assessment = scorer.calculate_risk(features, anomaly_prob, detector.version)
        decision = engine.evaluate(assessment, endpoint=req.path)

    # Attack should be classified as high risk & blocked
    assert decision.decision in [ActionEnum.CHALLENGE, ActionEnum.BLOCK]
    assert assessment.risk_score >= 40.0

    # 3. Simulate Instance Failure on app-2
    rec_success = await test_controller.execute_autonomous_recovery(
        instance_id="app-2",
        trigger_reason="Test workload degradation",
    )
    assert rec_success is True

    # 4. Verify Recovery Sequence & Events
    timeline = test_controller.get_timeline()
    event_types = [e.event_type for e in timeline]

    assert RecoveryEventType.INSTANCE_UNHEALTHY in event_types
    assert RecoveryEventType.INSTANCE_ISOLATED in event_types
    assert RecoveryEventType.TRAFFIC_REROUTED in event_types
    assert RecoveryEventType.REPLACEMENT_STARTED in event_types
    assert RecoveryEventType.REPLACEMENT_HEALTHY in event_types
    assert RecoveryEventType.INSTANCE_REINTRODUCED in event_types
    assert RecoveryEventType.SERVICE_RECOVERY_VERIFIED in event_types

    # 5. Verify Final Recovery Confidence
    metrics = test_controller.calculate_recovery_confidence()
    assert metrics.recovery_confidence >= 85.0

    # 6. Reset
    test_controller.reset_recovery_state()
    assert len(test_controller.get_timeline()) == 0
    assert len(test_registry.get_active_instances()) == 3


# =========================================================================
# 2. Fail-Safe Detector Fallback Test
# =========================================================================

def test_detector_failsafe_fallback():
    """Verify that if the ML model is missing or fails, statistical detection acts as safe fallback."""
    # Initialize detector with non-existent model path
    fallback_detector = ModularDetectorEngine(model_path="non_existent_model.joblib")
    assert fallback_detector.rf_detector.is_loaded is False

    extractor = FeatureExtractor(window_duration_seconds=5.0)
    req = IncomingRequest(
        client_ip="198.51.100.99",
        method="GET",
        path="/api/expensive-operation",
        timestamp=time.time(),
        user_agent="FloodAgent",
    )
    features = extractor.extract_features(req)

    # Predict should use heuristic/statistical fallback without raising exceptions
    prob = fallback_detector.predict_anomaly_probability(features)
    assert isinstance(prob, float)
    assert 0.0 <= prob <= 1.0


# =========================================================================
# 3. Availability During Isolation Test
# =========================================================================

def test_availability_during_isolation(test_registry):
    """Verify healthy instances continue serving traffic when an instance is isolated."""
    # Isolate app-2
    test_registry.isolate_instance("app-2")

    # Sample next 10 routed instances
    routed = [test_registry.get_active_healthy_instance().instance_id for _ in range(10)]

    # app-2 should never be returned
    assert "app-2" not in routed
    # app-1 and app-3 should alternate
    assert set(routed) == {"app-1", "app-3"}


# =========================================================================
# 4. Internal Workload Tagging Test
# =========================================================================

def test_internal_workload_attack_origin():
    """Verify internal microservice attacks are correctly tagged."""
    extractor = FeatureExtractor(window_duration_seconds=5.0)
    scorer = RiskScorer()

    req = IncomingRequest(
        client_ip="10.0.1.200",
        method="POST",
        path="/api/login",
        timestamp=time.time(),
        user_agent="Internal-Compromised-Worker/1.0",
        source_type=AttackSourceType.INTERNAL_COMPROMISED,
    )
    features = extractor.extract_features(req)
    assessment = scorer.calculate_risk(features, anomaly_probability=0.8, detector_version="v2.0-test")

    assert assessment.threat_level in [ThreatLevel.MEDIUM, ThreatLevel.HIGH]
    assert any("internal" in reason.lower() for reason in assessment.contributing_reasons)


# =========================================================================
# 5. Demo Reset Idempotency Test
# =========================================================================

def test_demo_reset_idempotency(gateway_client):
    """Verify reset can be invoked repeatedly without race conditions or errors."""
    for _ in range(5):
        resp = gateway_client.post("/api/demo/reset")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"

    # Status should show clean state
    status_resp = gateway_client.get("/api/recovery/status")
    assert status_resp.status_code == 200
    assert len(status_resp.json()["active_healthy_pool"]) >= 1


# =========================================================================
# 6. Offline Evaluation Metric Calculation Test
# =========================================================================

def test_evaluation_metrics_computation():
    """Verify precision, recall, F1 computation returns mathematically valid figures."""
    metrics = evaluate_detector_quality()
    assert 0.0 <= metrics["precision"] <= 1.0
    assert 0.0 <= metrics["recall"] <= 1.0
    assert 0.0 <= metrics["f1_score"] <= 1.0
    assert metrics["average_pipeline_latency_ms"] >= 0.0
    assert metrics["samples_evaluated"] > 50
