"""Phase 0 Foundation Smoke & Unit Tests."""

import pytest
from fastapi.testclient import TestClient

from onechance.core.detector import AnomalyDetector
from onechance.core.feature_extractor import FeatureExtractor
from onechance.core.mitigator import Mitigator
from onechance.core.policy_engine import PolicyEngine
from onechance.core.risk_scorer import RiskScorer
from onechance.recovery.recovery_controller import RecoveryController
from onechance.main import app
from onechance.models.decisions import ActionEnum
from onechance.models.traffic import AttackSourceType, IncomingRequest
from target_service.app import app as target_app


@pytest.fixture
def gateway_client():
    return TestClient(app)


@pytest.fixture
def target_client():
    return TestClient(target_app)


def test_target_service_health(target_client):
    """Verify target service health check endpoint responds with 200."""
    response = target_client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["is_healthy"] is True


def test_gateway_health(gateway_client):
    """Verify gateway health endpoint."""
    response = gateway_client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["healthy", "degraded"]
    assert "gateway" in data


def test_feature_extractor_sliding_window():
    """Verify rolling request feature extraction."""
    extractor = FeatureExtractor(window_duration_seconds=10.0)
    req = IncomingRequest(
        client_ip="192.168.1.50",
        method="GET",
        path="/api/data",
        timestamp=1000.0,
        source_type=AttackSourceType.EXTERNAL,
    )
    features = extractor.extract_features(req)
    assert features.client_ip == "192.168.1.50"
    assert features.request_rate_per_sec > 0.0


def test_risk_scorer_and_policy_engine():
    """Verify multi-signal risk calculation and 3-tier policy triage."""
    extractor = FeatureExtractor(window_duration_seconds=10.0)
    scorer = RiskScorer()
    engine = PolicyEngine()
    
    req = IncomingRequest(
        client_ip="192.168.1.100",
        method="GET",
        path="/api/data",
        timestamp=1000.0,
        source_type=AttackSourceType.EXTERNAL,
    )
    features = extractor.extract_features(req)
    assessment = scorer.calculate_risk(features, anomaly_probability=0.1)
    assert 0.0 <= assessment.risk_score <= 100.0

    decision = engine.evaluate(assessment)
    assert decision.action in [ActionEnum.ALLOW, ActionEnum.CHALLENGE, ActionEnum.BLOCK]


def test_mitigator_block_and_unblock():
    """Verify blocklist expiry and fast-path check."""
    mit = Mitigator()
    test_ip = "10.0.0.99"
    assert mit.is_blocked(test_ip)[0] is False

    from onechance.models.decisions import PolicyDecision
    block_decision = PolicyDecision(
        action=ActionEnum.BLOCK,
        client_ip=test_ip,
        risk_score=95.0,
        reason="Test high risk score",
        block_duration_seconds=10,
    )
    mit.apply_decision(block_decision)
    is_blocked, remaining = mit.is_blocked(test_ip)
    assert is_blocked is True
    assert remaining is not None and remaining > 0

    mit.unblock_ip(test_ip)
    assert mit.is_blocked(test_ip)[0] is False


def test_recovery_timeline_recording():
    """Verify recovery controller timeline logging."""
    controller = RecoveryController()
    event = controller.record_event(
        action="ISOLATE",
        target_instance="target-instance-primary",
        status="SUCCESS",
        trigger_reason="Test isolation trigger",
    )
    assert event.action == "ISOLATE"
    timeline = controller.get_timeline()
    assert len(timeline) >= 1
    assert any(e.event_id == event.event_id for e in timeline)
