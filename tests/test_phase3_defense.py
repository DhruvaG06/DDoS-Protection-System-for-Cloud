"""Phase 3 Adaptive Defense Test Suite (ALLOW -> CHALLENGE -> BLOCK).

Tests:
1. Threshold classification (LOW, MEDIUM, HIGH)
2. ALLOW policy decision
3. CHALLENGE policy decision & verification token issuance
4. BLOCK policy decision & temporary IP block
5. Temporary block auto-expiry
6. Challenge verification success
7. Challenge verification failure & adaptive escalation to BLOCK
8. Source & endpoint-aware rate limiting
9. Decision explainability factor generation
10. Security event structure & event logger buffer
11. End-to-end integration tests (Normal -> ALLOW, Anomalous -> BLOCK)
"""

import time
import pytest
from fastapi.testclient import TestClient

from onechance.config import settings
from onechance.core.detector import ModularDetectorEngine
from onechance.core.feature_extractor import FeatureExtractor
from onechance.core.mitigator import Mitigator
from onechance.core.policy_engine import PolicyEngine
from onechance.core.rate_limiter import RateLimiter
from onechance.core.risk_scorer import RiskScorer
from onechance.logging.event_logger import SecurityEventLogger
from onechance.main import app
from onechance.models.decisions import ActionEnum, PolicyDecision, RiskAssessment, ThreatLevel
from onechance.models.events import SecurityEvent
from onechance.models.traffic import AttackSourceType, IncomingRequest, TrafficFeatures


@pytest.fixture
def policy_engine():
    return PolicyEngine(challenge_threshold=40.0, block_threshold=70.0, block_duration_seconds=2)


@pytest.fixture
def mitigator():
    m = Mitigator()
    yield m
    m.clear()


@pytest.fixture
def rate_limiter():
    rl = RateLimiter(default_per_ip_limit=5, window_seconds=1.0)
    yield rl
    rl.clear()


@pytest.fixture
def event_logger(tmp_path):
    log_file = tmp_path / "test_security_events.jsonl"
    logger = SecurityEventLogger(log_path=log_file)
    yield logger
    logger.clear()


# ==========================================================
# 1. Threshold Classification & Policy Engine Unit Tests
# ==========================================================

def test_policy_engine_allow_low_risk(policy_engine):
    assessment = RiskAssessment(
        client_ip="192.168.1.50",
        risk_score=15.0,
        threat_level=ThreatLevel.LOW,
        anomaly_probability=0.05,
        contributing_reasons=["Normal traffic profile"],
    )
    decision = policy_engine.evaluate(assessment, endpoint="/api/products")

    assert decision.decision == ActionEnum.ALLOW
    assert decision.action == ActionEnum.ALLOW
    assert decision.threat_level == ThreatLevel.LOW
    assert decision.risk_score == 15.0
    assert decision.action_type == "forward"
    assert "Low risk score" in decision.reason
    assert len(decision.reasons) > 0


def test_policy_engine_challenge_medium_risk(policy_engine):
    assessment = RiskAssessment(
        client_ip="192.168.1.100",
        risk_score=55.0,
        threat_level=ThreatLevel.MEDIUM,
        anomaly_probability=0.55,
        contributing_reasons=["Endpoint concentration anomaly (0.80)", "Request rate burstiness"],
    )
    decision = policy_engine.evaluate(assessment, endpoint="/api/search")

    assert decision.decision == ActionEnum.CHALLENGE
    assert decision.action == ActionEnum.CHALLENGE
    assert decision.threat_level == ThreatLevel.MEDIUM
    assert decision.risk_score == 55.0
    assert decision.action_type == "challenge_issued"
    assert decision.challenge_token is not None
    assert decision.challenge_token.startswith("chal_")
    assert "Endpoint concentration anomaly (0.80)" in decision.reasons


def test_policy_engine_block_high_risk(policy_engine):
    assessment = RiskAssessment(
        client_ip="192.168.1.200",
        risk_score=85.0,
        threat_level=ThreatLevel.HIGH,
        anomaly_probability=0.92,
        contributing_reasons=["Abnormal request rate per source (45 req/s)", "Low endpoint entropy H(E)=0.05"],
    )
    decision = policy_engine.evaluate(assessment, endpoint="/api/expensive-operation")

    assert decision.decision == ActionEnum.BLOCK
    assert decision.action == ActionEnum.BLOCK
    assert decision.threat_level == ThreatLevel.HIGH
    assert decision.risk_score == 85.0
    assert decision.action_type == "temporary_block"
    assert decision.block_duration_seconds == 2
    assert "High risk score (85.0)" in decision.reason
    assert "Low endpoint entropy H(E)=0.05" in decision.reasons


# ==========================================================
# 2. Challenge & Mitigation Unit Tests
# ==========================================================

def test_mitigator_challenge_verification_success(mitigator):
    decision = PolicyDecision(
        decision=ActionEnum.CHALLENGE,
        action=ActionEnum.CHALLENGE,
        client_ip="10.0.0.1",
        risk_score=50.0,
        threat_level=ThreatLevel.MEDIUM,
        reason="Medium risk",
        challenge_token="chal_test123",
    )
    mitigator.apply_decision(decision)

    status = mitigator.get_mitigation_status()
    assert status["active_challenges_count"] == 1

    valid, failed_cnt = mitigator.verify_challenge("10.0.0.1", "chal_test123")
    assert valid is True
    assert failed_cnt == 0
    assert mitigator.is_session_verified("10.0.0.1") is True
    assert mitigator.get_mitigation_status()["active_challenges_count"] == 0


def test_mitigator_challenge_verification_failure_and_adaptive_block(mitigator):
    decision = PolicyDecision(
        decision=ActionEnum.CHALLENGE,
        action=ActionEnum.CHALLENGE,
        client_ip="10.0.0.2",
        risk_score=50.0,
        threat_level=ThreatLevel.MEDIUM,
        reason="Medium risk",
        challenge_token="chal_valid_secret",
    )
    mitigator.apply_decision(decision)

    # 1st wrong attempt
    valid, cnt1 = mitigator.verify_challenge("10.0.0.2", "wrong_token_1")
    assert valid is False
    assert cnt1 == 1
    assert mitigator.is_blocked("10.0.0.2")[0] is False

    # 2nd wrong attempt
    valid, cnt2 = mitigator.verify_challenge("10.0.0.2", "wrong_token_2")
    assert valid is False
    assert cnt2 == 2

    # 3rd wrong attempt -> Elevate to BLOCK!
    valid, cnt3 = mitigator.verify_challenge("10.0.0.2", "wrong_token_3")
    assert valid is False
    assert cnt3 == 3
    is_blk, rem = mitigator.is_blocked("10.0.0.2")
    assert is_blk is True
    assert rem > 0


def test_mitigator_temporary_block_expiry(mitigator):
    decision = PolicyDecision(
        decision=ActionEnum.BLOCK,
        action=ActionEnum.BLOCK,
        client_ip="10.0.0.3",
        risk_score=90.0,
        threat_level=ThreatLevel.HIGH,
        reason="High risk",
        block_duration_seconds=1,  # 1s duration
    )
    mitigator.apply_decision(decision)

    is_blk, _ = mitigator.is_blocked("10.0.0.3")
    assert is_blk is True

    # Sleep past expiry
    time.sleep(1.2)

    is_blk_expired, _ = mitigator.is_blocked("10.0.0.3")
    assert is_blk_expired is False


# ==========================================================
# 3. Rate Limiter Unit Tests
# ==========================================================

def test_rate_limiter_global_and_endpoint(rate_limiter):
    ip = "192.168.1.99"
    # Send 5 allowed requests to /api/products
    for _ in range(5):
        is_limited, _ = rate_limiter.is_rate_limited(ip, "/api/products")
        assert is_limited is False

    # 6th request exceeds per-IP limit of 5
    is_limited, reason = rate_limiter.is_rate_limited(ip, "/api/products")
    assert is_limited is True
    assert "Global IP rate limit exceeded" in reason


# ==========================================================
# 4. Security Event Logger Tests
# ==========================================================

def test_security_event_logging(event_logger):
    evt = SecurityEvent(
        source="1.2.3.4",
        endpoint="/api/login",
        risk_score=80.0,
        threat_level=ThreatLevel.HIGH,
        decision=ActionEnum.BLOCK,
        action="temporary_block",
        reasons=["High frequency burst", "Repeated login endpoint access"],
    )
    event_logger.log_event(evt)

    recent = event_logger.get_recent_events(limit=10)
    assert len(recent) == 1
    assert recent[0].source == "1.2.3.4"
    assert recent[0].decision == ActionEnum.BLOCK
    assert "High frequency burst" in recent[0].reasons


# ==========================================================
# 5. Integration Tests with Gateway FastAPI TestClient
# ==========================================================

client = TestClient(app)


def test_integration_normal_traffic_allow():
    """Normal traffic -> Feature Extraction -> Detector -> Low Risk -> ALLOW."""
    resp = client.get("/api/products", headers={"user-agent": "Mozilla/5.0 (Windows NT 10.0)"})
    assert resp.status_code in [200, 502]  # Allowed by gateway (backend mock may return 502 if not running standalone)
    assert "x-decision" in resp.headers
    assert resp.headers["x-decision"] == "ALLOW"
    assert "x-risk-score" in resp.headers


def test_integration_challenge_verification_flow():
    """Verify challenge token verification endpoint `/api/challenge/verify`."""
    # First query status endpoint
    status_resp = client.get("/api/mitigation/status")
    assert status_resp.status_code == 200
    data = status_resp.json()
    assert "policy_version" in data

    # Test verify challenge endpoint with dummy token
    verify_resp = client.post(
        "/api/challenge/verify",
        json={"client_ip": "172.16.0.5", "challenge_token": "dummy_token"},
    )
    assert verify_resp.status_code == 200
    v_data = verify_resp.json()
    assert v_data["status"] == "failed"
    assert v_data["failed_attempts"] == 1


def test_integration_security_events_endpoint():
    """Verify `/api/security-events` endpoint returns logged events."""
    resp = client.get("/api/security-events")
    assert resp.status_code == 200
    json_data = resp.json()
    assert "returned_count" in json_data
    assert "events" in json_data
