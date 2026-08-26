"""Automated Test Suite for Phase 2: Behavioral DDoS Detection & Explainable Risk Scoring."""

import time
import pytest
from fastapi.testclient import TestClient

from onechance.config import settings
from onechance.core.detector import HybridDetector, ModularDetectorEngine, RandomForestDetector
from onechance.core.feature_extractor import FeatureExtractor
from onechance.core.risk_scorer import RiskScorer
from onechance.main import app as gateway_app
from onechance.models.decisions import ThreatLevel
from onechance.models.traffic import AttackSourceType, IncomingRequest, TrafficFeatures


@pytest.fixture
def client():
    return TestClient(gateway_app)


# ==========================================================
# 1. Feature Extraction Unit Tests (10 Signals)
# ==========================================================

def test_feature_extractor_10_signals():
    """Verify all 10 behavioral signals are extracted accurately over rolling time window."""
    extractor = FeatureExtractor(window_duration_seconds=10.0)
    now = time.time()

    # Simulate 10 requests from client 192.168.1.100 targeting /api/products
    for i in range(10):
        req = IncomingRequest(
            client_ip="192.168.1.100",
            method="GET",
            path="/api/products",
            timestamp=now + (i * 0.2),
            status_code=200,
            latency_ms=25.0,
        )
        features = extractor.extract_features(req)

    assert features.requests_per_source == 10
    assert features.request_rate_per_sec == 1.0  # 10 req / 10s
    assert features.endpoint_concentration == 1.0  # 100% on /api/products
    assert features.repeated_pattern_score == 1.0  # 10 consecutive /api/products
    assert features.endpoint_entropy == 0.0  # single endpoint -> 0 Shannon entropy
    assert features.error_ratio == 0.0
    assert features.average_latency_ms == 25.0
    assert features.source_distribution_ratio == 1.0  # sole client IP in global window


def test_feature_extractor_diverse_traffic():
    """Verify entropy and error ratio calculation with diverse endpoints and status codes."""
    extractor = FeatureExtractor(window_duration_seconds=10.0)
    now = time.time()

    paths = ["/api/products", "/api/search", "/api/login", "/api/health"]
    for i in range(8):
        status_code = 404 if i % 4 == 0 else 200
        req = IncomingRequest(
            client_ip="10.0.0.5",
            method="GET",
            path=paths[i % 4],
            timestamp=now + (i * 0.1),
            status_code=status_code,
            latency_ms=40.0,
        )
        features = extractor.extract_features(req)

    assert features.requests_per_source == 8
    assert features.endpoint_distribution_ratio == 0.5  # 4 unique / 8 total
    assert features.endpoint_entropy > 1.5  # multiple endpoints -> high Shannon entropy
    assert features.error_ratio == 0.25  # 2 of 8 are 404s


# ==========================================================
# 2. Detector Modular Architecture & ML Model Tests
# ==========================================================

def test_hybrid_detector():
    """Test HybridDetector anomaly probability calculation."""
    detector = HybridDetector()
    assert detector.version == "v2.0-hybrid-rules"

    # Benign features
    benign_features = TrafficFeatures(
        client_ip="1.1.1.1",
        requests_per_source=5,
        request_rate_per_sec=0.5,
        endpoint_concentration=0.2,
        burstiness_score=1.2,
        repeated_pattern_score=0.2,
        endpoint_entropy=2.1,
    )
    benign_prob = detector.predict_anomaly_probability(benign_features)
    assert benign_prob < 0.20

    # Malicious flood features
    flood_features = TrafficFeatures(
        client_ip="2.2.2.2",
        requests_per_source=150,
        request_rate_per_sec=25.0,
        endpoint_concentration=0.95,
        burstiness_score=6.0,
        repeated_pattern_score=0.90,
        endpoint_entropy=0.1,
    )
    flood_prob = detector.predict_anomaly_probability(flood_features)
    assert flood_prob > 0.60

    importances = detector.get_feature_importances()
    assert "request_rate_per_sec" in importances


def test_random_forest_detector_integration():
    """Test Scikit-learn Random Forest model loading and inference."""
    rf_detector = RandomForestDetector(model_path=settings.DETECTOR_MODEL_PATH)
    assert rf_detector.is_loaded is True

    benign_features = TrafficFeatures(
        client_ip="1.1.1.1",
        requests_per_source=3,
        request_rate_per_sec=0.3,
        endpoint_concentration=0.33,
        burstiness_score=1.1,
        repeated_pattern_score=0.33,
        source_distribution_ratio=0.05,
        endpoint_distribution_ratio=0.66,
        endpoint_entropy=1.58,
        error_ratio=0.0,
        average_latency_ms=50.0,
    )
    prob_benign = rf_detector.predict_anomaly_probability(benign_features)
    assert prob_benign < 0.35

    attack_features = TrafficFeatures(
        client_ip="9.9.9.9",
        requests_per_source=250,
        request_rate_per_sec=25.0,
        endpoint_concentration=0.95,
        burstiness_score=8.5,
        repeated_pattern_score=0.95,
        source_distribution_ratio=0.85,
        endpoint_distribution_ratio=0.05,
        endpoint_entropy=0.1,
        error_ratio=0.1,
        average_latency_ms=1200.0,
    )
    prob_attack = rf_detector.predict_anomaly_probability(attack_features)
    assert prob_attack > 0.65


def test_modular_detector_engine_fallback(tmp_path):
    """Test detector engine fallback to HybridDetector if model path is invalid."""
    fake_path = str(tmp_path / "non_existent_model.joblib")
    engine = ModularDetectorEngine(model_path=fake_path)

    assert engine.rf_detector.is_loaded is False
    assert engine.active_detector.version == "v2.0-hybrid-rules"


# ==========================================================
# 3. Risk Scorer & Explainability Unit Tests
# ==========================================================

def test_risk_scorer_normal_traffic():
    """Verify normal traffic yields LOW risk score (0-39) with baseline reasoning."""
    scorer = RiskScorer()
    features = TrafficFeatures(
        client_ip="192.168.1.50",
        requests_per_source=4,
        request_rate_per_sec=0.4,
        endpoint_concentration=0.25,
        burstiness_score=1.2,
        repeated_pattern_score=0.25,
        source_distribution_ratio=0.1,
        endpoint_distribution_ratio=0.75,
        endpoint_entropy=1.8,
        error_ratio=0.0,
        average_latency_ms=35.0,
    )

    assessment = scorer.calculate_risk(features, anomaly_probability=0.05)
    assert assessment.risk_score <= 39.0
    assert assessment.threat_level == ThreatLevel.LOW
    assert len(assessment.contributing_reasons) > 0
    assert "Normal traffic behavior" in assessment.contributing_reasons[0]


def test_risk_scorer_anomalous_traffic_explainability():
    """Verify controlled anomalous traffic yields HIGH risk score (70-100) with detailed explainability."""
    scorer = RiskScorer()
    attack_features = TrafficFeatures(
        client_ip="45.33.22.11",
        requests_per_source=200,
        request_rate_per_sec=20.0,
        endpoint_concentration=0.95,
        burstiness_score=5.0,
        repeated_pattern_score=0.90,
        source_distribution_ratio=0.80,
        endpoint_distribution_ratio=0.05,
        endpoint_entropy=0.10,
        error_ratio=0.40,
        average_latency_ms=1500.0,
    )

    assessment = scorer.calculate_risk(attack_features, anomaly_probability=0.92)

    assert assessment.risk_score >= 70.0
    assert assessment.threat_level == ThreatLevel.HIGH
    assert len(assessment.contributing_reasons) >= 4

    # Verify specific explainability reasons are returned
    reasons_text = " ".join(assessment.contributing_reasons)
    assert "Abnormal request rate" in reasons_text or "High ML behavioral anomaly" in reasons_text
    assert "High endpoint concentration" in reasons_text
    assert "Repeated request pattern" in reasons_text
    assert "Endpoint entropy anomaly" in reasons_text
    assert "Elevated HTTP error ratio" in reasons_text or "High average request latency" in reasons_text


def test_risk_scorer_internal_compromised_workload():
    """Verify internal compromised workload triggers specific high-priority warning reason."""
    scorer = RiskScorer()
    internal_features = TrafficFeatures(
        client_ip="10.0.1.25",
        requests_per_source=30,
        request_rate_per_sec=3.0,
        endpoint_concentration=0.8,
        source_type=AttackSourceType.INTERNAL_COMPROMISED,
    )

    assessment = scorer.calculate_risk(internal_features, anomaly_probability=0.60)
    assert any("internal cloud workload" in r for r in assessment.contributing_reasons)


# ==========================================================
# 4. Gateway Detection API Endpoint Tests
# ==========================================================

def test_detection_assess_api_endpoint(client):
    """Test POST /api/detection/assess endpoint."""
    payload = {
        "client_ip": "172.16.0.42",
        "method": "POST",
        "path": "/api/login",
        "timestamp": time.time(),
        "status_code": 200,
        "latency_ms": 45.0,
        "source_type": "external",
    }
    response = client.post("/api/detection/assess", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert "risk_score" in data
    assert "threat_level" in data
    assert "features" in data
    assert "contributing_reasons" in data
    assert "detector_version" in data
    assert isinstance(data["risk_score"], float)


def test_detection_status_api_endpoint(client):
    """Test GET /api/detection/status endpoint."""
    response = client.get("/api/detection/status")
    assert response.status_code == 200
    data = response.json()

    assert "detector_version" in data
    assert "rf_model_loaded" in data
    assert "feature_importances" in data
    assert "thresholds" in data
    assert data["rf_model_loaded"] is True
